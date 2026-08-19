"""Asynchronous non-authoritative AI advisory outbox worker."""

from __future__ import annotations

import argparse
import json
import queue
import re
import threading
import time
from typing import Any, Callable, Dict, List, Mapping, Optional

from production.ai_advisory.contracts import (
    AIAdvisoryContractError,
    contract_schema_sha256,
    load_ai_advisory_policy,
    provider_output_json_schema,
    sha256_json,
    validate_provider_output,
)
from production.ai_advisory.contracts_v2 import (
    DEFAULT_PROJECTION_CONTRACT_PATH,
    build_deterministic_abstention_v2,
    contract_schema_sha256_v2,
    provider_output_json_schema_v2,
    validate_provider_output_v2,
    validate_validated_output_v2,
)
from production.ai_advisory.integration_v2 import (
    V1_TASK_SCHEMA,
    V2_RECORD_SCHEMA,
    V2_TASK_SCHEMA,
    load_ai_advisory_contract,
    request_identity_material_v2,
    validate_ai_advisory_record_v2,
    v2_invocation_eligibility,
)
from production.ai_advisory.projection import (
    build_ai_advisory_projection,
    build_ai_advisory_projection_v2,
    restore_validated_output_aliases,
)
from production.ai_advisory.provider import (
    AIAdvisoryProvider,
    AIProviderUnavailable,
    build_ai_advisory_provider,
)
from production.ai_advisory.rendering import (
    render_validated_advisory,
    render_validated_advisory_v2,
)
from production.ai_advisory.security import (
    AssessmentAliasScope,
    ProviderAliasScope,
    load_provider_alias_key,
)
from production.storage import open_existing_storage
from production.utils.config import ProductionConfig
from production.utils.sensitive_data import redact_exception_for_log
from production.utils.serialization import stable_id, stable_json, utc_now
from production.utils.service_lifecycle import ServiceLifecycle
from production.workers.job_lifecycle import JobLeaseHeartbeat, new_job_owner


TASK_KEYS_V1 = {"schema_version", "report_id", "session_id", "assessment_id"}
TASK_KEYS_V2 = {
    "schema_version",
    "report_id",
    "session_id",
    "assessment_id",
    "report_content_sha256",
    "advisory_contract_version",
}
ZERO_SHA256 = "0" * 64
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PROVIDER_USAGE_INTEGER_KEYS = frozenset(
    {
        "prompt_token_count",
        "candidates_token_count",
        "thoughts_token_count",
        "total_token_count",
        "cached_content_token_count",
        "tool_use_prompt_token_count",
    }
)


def _identity_text(value: Any, label: str, *, allow_empty: bool = False) -> str:
    text = str(value or "")
    if not text and allow_empty:
        return ""
    if not text or not _SAFE_ID_RE.fullmatch(text):
        raise AIAdvisoryContractError(
            f"provider {label} identity is invalid",
            code="provider_identity_invalid",
        )
    return text


def _identity_hash(value: Any, label: str, *, allow_empty: bool = False) -> str:
    text = str(value or "").lower()
    if not text and allow_empty:
        return ""
    if not _SHA256_RE.fullmatch(text):
        raise AIAdvisoryContractError(
            f"provider {label} identity hash is invalid",
            code="provider_identity_invalid",
        )
    return text


def _retry_delay(config: ProductionConfig, attempts: int) -> float:
    exponent = min(max(int(attempts) - 1, 0), 31)
    return min(
        float(config.ai_advisory_retry_max_seconds),
        float(config.ai_advisory_retry_base_seconds) * (2**exponent),
    )


def _provider_usage_metrics(response: Any) -> Dict[str, Any]:
    """Accept only aggregate, non-negative provider usage telemetry."""

    raw = getattr(response, "usage_metadata", {})
    if not isinstance(raw, Mapping):
        return {}
    result: Dict[str, Any] = {}
    for key in _PROVIDER_USAGE_INTEGER_KEYS:
        value = raw.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            result[f"provider_{key}"] = value
    traffic_type = raw.get("traffic_type")
    if isinstance(traffic_type, str) and re.fullmatch(
        r"[A-Z][A-Z0-9_]{0,63}", traffic_type
    ):
        result["provider_traffic_type"] = traffic_type
    return result


def _safe_log(payload: Mapping[str, Any]) -> None:
    allowed = {
        "service",
        "job_id",
        "status",
        "error_code",
        "error_type",
        "attempts",
        "latency_ms",
        "cache_hit",
        "timestamp",
    }
    print(
        json.dumps(
            {key: payload[key] for key in allowed if key in payload},
            sort_keys=True,
        ),
        flush=True,
    )


class AIAdvisoryWorker:
    """Consume report references without ever modifying canonical records."""

    def __init__(
        self,
        config: ProductionConfig,
        provider: Optional[AIAdvisoryProvider] = None,
        *,
        storage: Any = None,
    ) -> None:
        self.config = config
        # Canonical migrations and full integrity scans are deployment gates.
        # This optional worker joins an already initialized database through a
        # bounded, read-only schema/ledger readiness check.
        self.storage = storage or open_existing_storage(config.database_settings())
        (
            self.policy,
            self.policy_sha256,
            self.policy_path,
            self.contract_version,
        ) = load_ai_advisory_contract(config.ai_advisory_policy_path)
        self.provider = provider or build_ai_advisory_provider(config)
        self.prompt_sha256 = sha256_json(self.policy["prompt_contract"])
        if self.contract_version == "v2":
            self.response_schema = provider_output_json_schema_v2(self.policy)
            self.schema_sha256 = contract_schema_sha256_v2(self.policy)
            self.projection_contract_path = str(DEFAULT_PROJECTION_CONTRACT_PATH)
        else:
            self.response_schema = provider_output_json_schema(self.policy)
            self.schema_sha256 = contract_schema_sha256(self.policy)
            self.projection_contract_path = ""
        self.worker_owner = new_job_owner("ai-advisory")
        self.alias_key = (
            load_provider_alias_key(config.ai_advisory_alias_key_file)
            if config.enable_ai_advisory
            else b""
        )
        self._provider_call_thread: threading.Thread | None = None

    def _alias_scope(self) -> ProviderAliasScope:
        provider_scope = sha256_json(
            {
                "provider_id": str(getattr(self.provider, "provider_id", "") or ""),
                "model_id": str(getattr(self.provider, "model_id", "") or ""),
                "adapter_revision": str(
                    getattr(self.provider, "adapter_revision", "")
                    or self.config.ai_advisory_adapter_revision
                ),
                "endpoint": self.config.ai_advisory_endpoint,
                "api_version": self.config.ai_advisory_api_version,
            }
        )
        return ProviderAliasScope(self.alias_key, provider_scope)

    def _v2_alias_scope(self, assessment_id: str) -> AssessmentAliasScope:
        provider_id = str(getattr(self.provider, "provider_id", "") or "").strip()
        if not provider_id:
            provider_id = "unconfigured"
        return AssessmentAliasScope(
            self.alias_key,
            provider_id=provider_id,
            assessment_id=str(assessment_id or "").strip(),
        )

    def _call_provider_with_deadline(
        self,
        projection: Mapping[str, Any],
        identity: Mapping[str, str],
    ) -> Any:
        """Bound even an adapter that fails to honor its transport timeout."""

        if (
            self._provider_call_thread is not None
            and self._provider_call_thread.is_alive()
        ):
            raise AIProviderUnavailable(
                "previous AI advisory provider call is still outstanding"
            )

        result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

        def invoke() -> None:
            try:
                result_queue.put(
                    (
                        True,
                        self.provider.generate(
                            projection,
                            prompt_contract=self.policy["prompt_contract"],
                            response_schema=self.response_schema,
                            schema_sha256=self.schema_sha256,
                            policy_sha256=str(
                                projection["provenance"]["ai_policy_sha256"]
                            ),
                            timeout_seconds=self.config.ai_advisory_timeout_seconds,
                            max_response_bytes=min(
                                self.config.ai_advisory_max_response_bytes,
                                int(self.policy["limits"]["max_response_bytes"]),
                            ),
                            idempotency_key=identity["request_sha256"],
                        ),
                    )
                )
            except BaseException as exc:
                result_queue.put((False, exc))

        thread = threading.Thread(
            target=invoke,
            name="ai-provider-call",
            daemon=True,
        )
        self._provider_call_thread = thread
        thread.start()
        thread.join(float(self.config.ai_advisory_timeout_seconds))
        if thread.is_alive():
            raise AIProviderUnavailable("AI advisory provider deadline exceeded")
        self._provider_call_thread = None
        succeeded, value = result_queue.get_nowait()
        if not succeeded:
            if isinstance(value, Exception):
                raise value
            raise AIProviderUnavailable("AI advisory provider failed")
        return value

    def _validate_task(self, job: Mapping[str, Any]) -> Dict[str, str]:
        task = job.get("task")
        if not isinstance(task, Mapping):
            raise AIAdvisoryContractError("AI advisory task contract is invalid")
        task_schema = str(task.get("schema_version") or "")
        expected_keys = TASK_KEYS_V2 if task_schema == V2_TASK_SCHEMA else TASK_KEYS_V1
        if set(task) != expected_keys:
            raise AIAdvisoryContractError("AI advisory task contract is invalid")
        if task_schema not in {V1_TASK_SCHEMA, V2_TASK_SCHEMA}:
            raise AIAdvisoryContractError("AI advisory task schema is invalid")
        if task_schema != f"ai_advisory_task.{self.contract_version}":
            raise AIAdvisoryContractError("AI advisory task version does not match worker")
        result = {
            key: str(task.get(key) or "").strip()
            for key in ("report_id", "session_id", "assessment_id")
        }
        if any(not value for value in result.values()):
            raise AIAdvisoryContractError("AI advisory task identity is missing")
        for key, value in result.items():
            if value != str(job.get(key) or ""):
                raise AIAdvisoryContractError(
                    f"AI advisory task {key} does not match its outbox row"
                )
        result["task_schema"] = task_schema
        if task_schema == V2_TASK_SCHEMA:
            if task.get("advisory_contract_version") != "v2":
                raise AIAdvisoryContractError(
                    "v2 task advisory contract version is invalid"
                )
            report_hash = str(task.get("report_content_sha256") or "").lower()
            if not _SHA256_RE.fullmatch(report_hash):
                raise AIAdvisoryContractError(
                    "v2 task report_content_sha256 is invalid"
                )
            result["report_content_sha256"] = report_hash
        return result

    def _request_identity(self, projection: Mapping[str, Any]) -> Dict[str, str]:
        provider_id = _identity_text(
            getattr(self.provider, "provider_id", ""), "provider_id", allow_empty=True
        )
        model_id = _identity_text(
            getattr(self.provider, "model_id", ""), "model_id", allow_empty=True
        )
        adapter_revision = _identity_text(
            getattr(
                self.provider,
                "adapter_revision",
                self.config.ai_advisory_adapter_revision,
            )
            or self.config.ai_advisory_adapter_revision,
            "adapter_revision",
        )
        endpoint_sha256 = _identity_hash(
            getattr(self.provider, "endpoint_sha256", "")
            or sha256_json(
                {
                    "status": (
                        "configured"
                        if self.config.ai_advisory_endpoint
                        else "not_configured"
                    ),
                    "endpoint": self.config.ai_advisory_endpoint,
                }
            ),
            "endpoint",
        )
        api_version = _identity_text(
            getattr(self.provider, "api_version", "")
            or self.config.ai_advisory_api_version
            or "not_configured",
            "api_version",
        )
        request_options_sha256 = _identity_hash(
            getattr(self.provider, "request_options_sha256", "")
            or sha256_json(self.config.ai_advisory_request_options),
            "request_options",
        )
        request_material = self._request_material(projection)
        request_bytes = len(stable_json(request_material).encode("utf-8"))
        request_tokens = (request_bytes + 3) // 4
        provider_identity = {
            "provider_id": provider_id,
            "model_id": model_id,
            "adapter_revision": adapter_revision,
            "endpoint_sha256": endpoint_sha256,
            "api_version": api_version,
            "request_options_sha256": request_options_sha256,
        }
        request_limits = {
            "max_bytes": min(
                self.config.ai_advisory_max_request_bytes,
                int(self.policy["limits"]["max_request_bytes"]),
            ),
            "max_tokens": min(
                self.config.ai_advisory_max_request_tokens,
                int(self.policy["limits"]["max_request_tokens"]),
            ),
        }
        if self.contract_version == "v2":
            request_material = request_identity_material_v2(
                projection,
                provider_identity=provider_identity,
                prompt_sha256=self.prompt_sha256,
                schema_sha256=self.schema_sha256,
                policy_sha256=projection["provenance"]["ai_policy_sha256"],
                request_bytes=request_bytes,
                request_tokens=request_tokens,
                request_limits=request_limits,
            )
        else:
            request_material = {
                "projection": projection,
                "provider_identity": provider_identity,
                "prompt_sha256": self.prompt_sha256,
                "schema_sha256": self.schema_sha256,
                "policy_sha256": projection["provenance"]["ai_policy_sha256"],
                "request_bytes": request_bytes,
                "request_tokens": request_tokens,
                "request_limits": request_limits,
            }
        request_sha256 = sha256_json(request_material)
        return {
            "provider_id": provider_id,
            "model_id": model_id,
            "adapter_revision": adapter_revision,
            "endpoint_sha256": endpoint_sha256,
            "api_version": api_version,
            "request_options_sha256": request_options_sha256,
            "request_bytes": str(request_bytes),
            "request_tokens": str(request_tokens),
            "request_sha256": request_sha256,
            "cache_key": stable_id(
                "ai_advisory_cache",
                {
                    "request_sha256": request_sha256,
                    "projection_sha256": projection["projection_sha256"],
                },
            ),
        }

    def _request_material(self, projection: Mapping[str, Any]) -> Dict[str, Any]:
        """Return the exact deterministic material sent to a future adapter."""
        return {
            "projection": projection,
            "prompt_contract": self.policy["prompt_contract"],
            "response_schema": self.response_schema,
            "schema_sha256": self.schema_sha256,
            "policy_sha256": projection["provenance"]["ai_policy_sha256"],
        }

    def _enforce_request_budget(self, identity: Mapping[str, str]) -> None:
        request_bytes = int(identity["request_bytes"])
        request_tokens = int(identity["request_tokens"])
        max_bytes = min(
            int(self.config.ai_advisory_max_request_bytes),
            int(self.policy["limits"]["max_request_bytes"]),
        )
        max_tokens = min(
            int(self.config.ai_advisory_max_request_tokens),
            int(self.policy["limits"]["max_request_tokens"]),
        )
        if request_bytes > max_bytes or request_tokens > max_tokens:
            raise AIAdvisoryContractError(
                "AI advisory request exceeds the deterministic size/token budget",
                code="request_budget_exceeded",
            )

    @staticmethod
    def _cached_record(
        row: Mapping[str, Any], task: Mapping[str, str]
    ) -> Dict[str, Any]:
        same_report = (
            str(row.get("report_id") or "") == task["report_id"]
            and str(row.get("assessment_id") or "") == task["assessment_id"]
        )
        advisory_id = str(row["advisory_id"])
        cache_key = str(row["cache_key"])
        if not same_report:
            # Keep a report-specific local association without another provider
            # call. This prevents a cache hit for an older report from being
            # displayed as the current report's advisory.
            cache_key = stable_id(
                "ai_advisory_report_cache_link",
                {
                    "source_cache_key": cache_key,
                    "report_id": task["report_id"],
                    "assessment_id": task["assessment_id"],
                },
            )
            advisory_id = stable_id(
                "ai_advisory_report_link",
                {"cache_key": cache_key, "source_advisory_id": advisory_id},
            )
        metrics = dict(row["metrics"])
        metrics["cache_hit"] = True
        return {
            "advisory_id": advisory_id,
            "cache_key": cache_key,
            "report_id": task["report_id"],
            "session_id": task["session_id"],
            "assessment_id": task["assessment_id"],
            "status": row["status"],
            "projection_sha256": row["projection_sha256"],
            "request_sha256": row["request_sha256"],
            "response_sha256": row["response_sha256"],
            "provider_id": row["provider_id"],
            "model_id": row["model_id"],
            "prompt_sha256": row["prompt_sha256"],
            "schema_sha256": row["schema_sha256"],
            "policy_sha256": row["policy_sha256"],
            "payload": row["payload"],
            "metrics": metrics,
        }

    def _record(
        self,
        *,
        task: Mapping[str, str],
        identity: Mapping[str, str],
        projection: Mapping[str, Any],
        status: str,
        response_sha256: str,
        payload: Mapping[str, Any],
        metrics: Mapping[str, Any],
    ) -> Dict[str, Any]:
        advisory_id = stable_id(
            "ai_advisory",
            {
                "cache_key": identity["cache_key"],
                "status": status,
                "response_sha256": response_sha256,
                "payload": payload,
            },
        )
        return {
            "advisory_id": advisory_id,
            "cache_key": identity["cache_key"],
            "report_id": task["report_id"],
            "session_id": task["session_id"],
            "assessment_id": task["assessment_id"],
            "status": status,
            "projection_sha256": projection["projection_sha256"],
            "request_sha256": identity["request_sha256"],
            "response_sha256": response_sha256,
            "provider_id": identity["provider_id"] or "unavailable",
            "model_id": identity["model_id"],
            "prompt_sha256": self.prompt_sha256,
            "schema_sha256": self.schema_sha256,
            "policy_sha256": self.policy_sha256,
            "payload": dict(payload),
            "metrics": dict(metrics),
        }

    def _v2_provenance(
        self,
        *,
        report: Mapping[str, Any],
        projection: Mapping[str, Any],
        identity: Mapping[str, str],
        response_sha256: str,
        provider_id: str,
        model_id: str,
    ) -> dict[str, Any]:
        evidence = report.get("canonical_evidence") or {}
        graph = evidence.get("semantic_graph") or {}
        guidance = report.get("response_guidance_v4") or {}
        return {
            "report_content_sha256": str(report.get("report_content_sha256") or ""),
            "projection_sha256": projection["projection_sha256"],
            "evidence_sha256": str(evidence.get("evidence_sha256") or ""),
            "graph_sha256": str(graph.get("graph_sha256") or ""),
            "typed_fact_set_sha256": str(graph.get("typed_fact_set_sha256") or ""),
            "guidance_content_sha256": str(guidance.get("content_sha256") or ""),
            "request_sha256": identity["request_sha256"],
            "response_sha256": response_sha256,
            "provider_id": provider_id,
            "model_id": model_id,
            "prompt_sha256": self.prompt_sha256,
            "schema_sha256": self.schema_sha256,
            "policy_sha256": self.policy_sha256,
            "projection_contract_sha256": str(
                (projection.get("provenance") or {}).get(
                    "projection_contract_sha256"
                )
                or ""
            ),
            "provider_identity": {
                "adapter_revision": identity["adapter_revision"],
                "endpoint_sha256": identity["endpoint_sha256"],
                "api_version": identity["api_version"],
                "request_options_sha256": identity["request_options_sha256"],
            },
            "request_budget": {
                "request_bytes": int(identity["request_bytes"]),
                "request_tokens_estimate": int(identity["request_tokens"]),
                "max_request_bytes": min(
                    self.config.ai_advisory_max_request_bytes,
                    int(self.policy["limits"]["max_request_bytes"]),
                ),
                "max_request_tokens": min(
                    self.config.ai_advisory_max_request_tokens,
                    int(self.policy["limits"]["max_request_tokens"]),
                ),
            },
        }

    @staticmethod
    def _v2_safety() -> dict[str, Any]:
        return {
            "requires_manual_approval": True,
            "safe_to_auto_execute": False,
            "alerts_authorized": False,
            "response_actions_authorized": False,
        }

    def _v2_record_payload(
        self,
        *,
        status: str,
        validation_status: str,
        reason_code: str,
        validated_output: Mapping[str, Any] | None,
        rendered: Mapping[str, Any] | None,
        provenance: Mapping[str, Any],
    ) -> dict[str, Any]:
        authority = (
            "non_authoritative_deterministic_abstention"
            if status == "abstained"
            else (
                "non_authoritative_rejected_output"
                if status == "rejected"
                else "non_authoritative_advisory_only"
            )
        )
        payload = {
            "schema_version": V2_RECORD_SCHEMA,
            "status": status,
            "authority": authority,
            "validation": {
                "status": validation_status,
                "reason_code": reason_code,
            },
            "validated_output": dict(validated_output or {}),
            "rendered_advisory": dict(rendered or {}),
            "safety": self._v2_safety(),
            "provenance": dict(provenance),
        }
        return validate_ai_advisory_record_v2(
            payload,
            projection_sha256=str(provenance.get("projection_sha256") or ""),
            policy_sha256=str(provenance.get("policy_sha256") or ""),
        )

    def _process_claim_v2(
        self,
        job: Mapping[str, Any],
        task: Mapping[str, str],
        *,
        renew_claim: Callable[[], None],
    ) -> str:
        report_row = self.storage.get_report_by_id(task["report_id"])
        if not report_row or not isinstance(report_row.get("payload"), Mapping):
            raise AIAdvisoryContractError("persisted canonical report is unavailable")
        report = report_row["payload"]
        if report.get("schema_version") != "session_assessment.v6":
            raise AIAdvisoryContractError("v2 advisory requires a current v6 report")
        if (
            str(report.get("assessment_id") or "") != task["assessment_id"]
            or str(report_row.get("session_id") or "") != task["session_id"]
            or str(report.get("report_content_sha256") or "").lower()
            != task.get("report_content_sha256")
        ):
            raise AIAdvisoryContractError("v2 report identity does not match task")
        alias_scope = self._v2_alias_scope(task["assessment_id"])
        projection = build_ai_advisory_projection_v2(
            report,
            alias_scope=alias_scope,
            ai_policy_path=self.policy_path,
            projection_contract_path=self.projection_contract_path,
        )
        identity = self._request_identity(projection)
        self._enforce_request_budget(identity)
        cached = self.storage.get_ai_advisory_by_cache_key(identity["cache_key"])
        if cached:
            cached_payload = cached.get("payload")
            validate_ai_advisory_record_v2(
                cached_payload,
                projection_sha256=projection["projection_sha256"],
                policy_sha256=self.policy_sha256,
            )
            renew_claim()
            completed = self.storage.complete_ai_advisory_job(
                job["job_id"],
                job["claim_owner"],
                job["claim_token"],
                self._cached_record(cached, task),
                completion_code="cache_replayed",
            )
            if not completed:
                raise RuntimeError("AI advisory cache completion lost its claim")
            return "cache_replayed"

        eligible, reason = v2_invocation_eligibility(projection)
        if not eligible:
            validated = build_deterministic_abstention_v2(
                projection=projection,
                report=report,
                alias_scope=alias_scope,
                reason_code=reason,
                policy_path=self.policy_path,
                projection_contract_path=self.projection_contract_path,
            )
            validated = validate_validated_output_v2(
                validated,
                projection=projection,
                report=report,
                alias_scope=alias_scope,
                policy_path=self.policy_path,
                projection_contract_path=self.projection_contract_path,
            )
            rendered = render_validated_advisory_v2(
                validated, projection=projection, policy=self.policy
            )
            response_sha256 = sha256_json(validated)
            no_call_identity = dict(identity)
            no_call_identity["provider_id"] = "deterministic_no_call"
            no_call_identity["model_id"] = ""
            payload = self._v2_record_payload(
                status="abstained",
                validation_status="accepted",
                reason_code=reason,
                validated_output=validated,
                rendered=rendered,
                provenance=self._v2_provenance(
                    report=report,
                    projection=projection,
                    identity=no_call_identity,
                    response_sha256=response_sha256,
                    provider_id="deterministic_no_call",
                    model_id="",
                ),
            )
            record = self._record(
                task=task,
                identity=no_call_identity,
                projection=projection,
                status="abstained",
                response_sha256=response_sha256,
                payload=payload,
                metrics={
                    "schema_valid": True,
                    "validator_accepted": True,
                    "validator_reason_code": reason,
                    "deterministic_no_call": True,
                    "provider_called": False,
                    "cache_hit": False,
                },
            )
            renew_claim()
            completed = self.storage.complete_ai_advisory_job(
                job["job_id"],
                job["claim_owner"],
                job["claim_token"],
                record,
                completion_code="deterministic_abstention",
            )
            if not completed:
                raise RuntimeError("AI advisory abstention lost its claim")
            return "abstained"

        response = self._call_provider_with_deadline(projection, identity)
        provider_usage = _provider_usage_metrics(response)
        computed_response_sha256 = sha256_json(response.structured_output)
        try:
            response_bytes = stable_json(response.structured_output).encode("utf-8")
            response_limit = min(
                self.config.ai_advisory_max_response_bytes,
                int(self.policy["limits"]["max_response_bytes"]),
            )
            if len(response_bytes) > response_limit:
                raise AIAdvisoryContractError(
                    "provider response exceeds the configured limit"
                )
            echoed_response_sha256 = str(response.response_sha256 or "")
            if not _SHA256_RE.fullmatch(echoed_response_sha256):
                raise AIAdvisoryContractError(
                    "provider response hash echo is invalid", code="hash_mismatch"
                )
            if echoed_response_sha256 != computed_response_sha256:
                raise AIAdvisoryContractError(
                    "provider response hash mismatch", code="hash_mismatch"
                )
            if (
                response.provider_id != identity["provider_id"]
                or response.model_id != identity["model_id"]
            ):
                raise AIAdvisoryContractError(
                    "provider response identity does not match the request",
                    code="provider_identity_mismatch",
                )
            for attribute in (
                "adapter_revision",
                "endpoint_sha256",
                "api_version",
                "request_options_sha256",
            ):
                echoed = str(getattr(response, attribute, "") or "")
                expected = str(identity.get(attribute) or "")
                if attribute.endswith("sha256"):
                    _identity_hash(echoed, attribute, allow_empty=True)
                else:
                    _identity_text(echoed, attribute, allow_empty=True)
                if echoed and echoed != expected:
                    raise AIAdvisoryContractError(
                        f"provider response {attribute} does not match the request",
                        code="provider_identity_mismatch",
                    )
            validated = validate_provider_output_v2(
                response.structured_output,
                projection=projection,
                report=report,
                alias_scope=alias_scope,
                policy_path=self.policy_path,
                projection_contract_path=self.projection_contract_path,
            )
            validated = validate_validated_output_v2(
                validated,
                projection=projection,
                report=report,
                alias_scope=alias_scope,
                policy_path=self.policy_path,
                projection_contract_path=self.projection_contract_path,
            )
            rendered = render_validated_advisory_v2(
                validated, projection=projection, policy=self.policy
            )
        except AIAdvisoryContractError as exc:
            payload = self._v2_record_payload(
                status="rejected",
                validation_status="rejected",
                reason_code=exc.code,
                validated_output=None,
                rendered=None,
                provenance=self._v2_provenance(
                    report=report,
                    projection=projection,
                    identity=identity,
                    response_sha256=computed_response_sha256,
                    provider_id=str(response.provider_id or "unavailable"),
                    model_id=str(response.model_id or ""),
                ),
            )
            record = self._record(
                task=task,
                identity=identity,
                projection=projection,
                status="rejected",
                response_sha256=computed_response_sha256,
                payload=payload,
                metrics={
                    "schema_valid": False,
                    "validator_accepted": False,
                    "validator_reason_code": exc.code,
                    "provider_called": True,
                    "cache_hit": False,
                    **provider_usage,
                },
            )
            renew_claim()
            completed = self.storage.complete_ai_advisory_job(
                job["job_id"],
                job["claim_owner"],
                job["claim_token"],
                record,
                completion_code="rejected",
            )
            if not completed:
                raise RuntimeError("AI advisory rejection lost its claim")
            return "rejected"

        synthesis = validated["synthesis"]
        status = "abstained" if synthesis["abstained"] else "accepted"
        payload = self._v2_record_payload(
            status=status,
            validation_status="accepted",
            reason_code=str(synthesis.get("abstention_reason_code") or ""),
            validated_output=validated,
            rendered=rendered,
            provenance=self._v2_provenance(
                report=report,
                projection=projection,
                identity=identity,
                response_sha256=computed_response_sha256,
                provider_id=str(response.provider_id or ""),
                model_id=str(response.model_id or ""),
            ),
        )
        record = self._record(
            task=task,
            identity=identity,
            projection=projection,
            status=status,
            response_sha256=computed_response_sha256,
            payload=payload,
            metrics={
                "schema_valid": True,
                "validator_accepted": True,
                "validator_reason_code": "",
                "provider_called": True,
                "cache_hit": False,
                "abstained": bool(synthesis["abstained"]),
                "selected_chain_count": len(synthesis["selected_chain_ids"]),
                "selected_finding_count": len(synthesis["ranked_finding_ids"]),
                "selected_action_count": len(synthesis["ranked_action_ids"]),
                "review_plan_step_count": len(synthesis["review_plan"]),
                **provider_usage,
            },
        )
        renew_claim()
        completed = self.storage.complete_ai_advisory_job(
            job["job_id"],
            job["claim_owner"],
            job["claim_token"],
            record,
            completion_code="accepted",
        )
        if not completed:
            raise RuntimeError("AI advisory completion lost its claim")
        return status

    def _process_claim(
        self,
        job: Mapping[str, Any],
        *,
        renew_claim: Callable[[], None],
    ) -> str:
        task = self._validate_task(job)
        if self.contract_version == "v2":
            return self._process_claim_v2(
                job, task, renew_claim=renew_claim
            )
        report_row = self.storage.get_report_by_id(task["report_id"])
        if not report_row or not isinstance(report_row.get("payload"), Mapping):
            raise AIAdvisoryContractError("persisted canonical report is unavailable")
        report = report_row["payload"]
        if (
            str(report.get("assessment_id") or "") != task["assessment_id"]
            or str(report_row.get("session_id") or "") != task["session_id"]
        ):
            raise AIAdvisoryContractError("persisted report identity does not match task")
        alias_scope = self._alias_scope()
        projection = build_ai_advisory_projection(
            report,
            policy=self.policy,
            policy_sha256=self.policy_sha256,
            alias_scope=alias_scope,
        )
        identity = self._request_identity(projection)
        self._enforce_request_budget(identity)
        cached = self.storage.get_ai_advisory_by_cache_key(identity["cache_key"])
        if cached:
            renew_claim()
            completed = self.storage.complete_ai_advisory_job(
                job["job_id"],
                job["claim_owner"],
                job["claim_token"],
                self._cached_record(cached, task),
                completion_code="cache_replayed",
            )
            if not completed:
                raise RuntimeError("AI advisory cache completion lost its claim")
            return "cache_replayed"

        response = self._call_provider_with_deadline(projection, identity)
        provider_usage = _provider_usage_metrics(response)
        try:
            computed_response_sha256 = sha256_json(response.structured_output)
            response_bytes = stable_json(response.structured_output).encode("utf-8")
            response_limit = min(
                self.config.ai_advisory_max_response_bytes,
                int(self.policy["limits"]["max_response_bytes"]),
            )
            if len(response_bytes) > response_limit:
                raise AIAdvisoryContractError("provider response exceeds the configured limit")
            echoed_response_sha256 = str(response.response_sha256 or "")
            if not _SHA256_RE.fullmatch(echoed_response_sha256):
                raise AIAdvisoryContractError(
                    "provider response hash echo is invalid",
                    code="hash_mismatch",
                )
            if echoed_response_sha256 != computed_response_sha256:
                raise AIAdvisoryContractError(
                    "provider response hash mismatch",
                    code="hash_mismatch",
                )
            if (
                response.provider_id != identity["provider_id"]
                or response.model_id != identity["model_id"]
            ):
                raise AIAdvisoryContractError(
                    "provider response identity does not match the request",
                    code="provider_identity_mismatch",
                )
            for attribute in (
                "adapter_revision",
                "endpoint_sha256",
                "api_version",
                "request_options_sha256",
            ):
                echoed = str(getattr(response, attribute, "") or "")
                expected = str(identity.get(attribute) or "")
                if attribute.endswith("sha256"):
                    _identity_hash(echoed, attribute, allow_empty=True)
                else:
                    _identity_text(echoed, attribute, allow_empty=True)
                if echoed and echoed != expected:
                    raise AIAdvisoryContractError(
                        f"provider response {attribute} does not match the request",
                        code="provider_identity_mismatch",
                    )
            validated = validate_provider_output(
                response.structured_output,
                projection=projection,
                policy=self.policy,
                policy_sha256=str(projection["provenance"]["ai_policy_sha256"]),
            )
            validated = restore_validated_output_aliases(validated, alias_scope)
            rendered = render_validated_advisory(
                validated,
                report=report,
                policy=self.policy,
            )
        except AIAdvisoryContractError as exc:
            payload = {
                "schema_version": "ai_advisory_record.v1",
                "status": "rejected",
                "authority": "non_authoritative_rejected_output",
                "validation": {"status": "rejected", "reason_code": exc.code},
                "validated_advisory": {},
                "rendered_advisory": {},
                "shadow_candidates": {
                    "schema_version": "ai_shadow_candidate_set.v1",
                    "candidates": [],
                },
            }
            record = self._record(
                task=task,
                identity=identity,
                projection=projection,
                status="rejected",
                response_sha256=computed_response_sha256,
                payload=payload,
                metrics={
                    "schema_valid": False,
                    "validator_accepted": False,
                    "validator_reason_code": exc.code,
                    "cache_hit": False,
                    **provider_usage,
                },
            )
            renew_claim()
            completed = self.storage.complete_ai_advisory_job(
                job["job_id"],
                job["claim_owner"],
                job["claim_token"],
                record,
                completion_code="rejected",
            )
            if not completed:
                raise RuntimeError("AI advisory rejection lost its claim")
            return "rejected"

        normalized_advisory = validated["validated_advisory"]
        shadow = validated["shadow_candidates"]
        evidence_refs = {
            ref
            for candidate in shadow["candidates"]
            for ref in candidate["premise_evidence_refs"]
        }
        payload = {
            "schema_version": "ai_advisory_record.v1",
            "status": "accepted",
            "authority": "non_authoritative_advisory_only",
            "validation": {"status": "accepted", "reason_code": ""},
            "validated_advisory": normalized_advisory,
            "rendered_advisory": rendered,
            "shadow_candidates": shadow,
            "safety": {
                "requires_manual_approval": True,
                "safe_to_auto_execute": False,
                "alerts_authorized": False,
                "response_actions_authorized": False,
            },
            "provenance": {
                "projection_sha256": projection["projection_sha256"],
                # Local audit records retain canonical local identity; only the
                # provider projection uses the provider-scoped alias digest.
                "evidence_sha256": str(
                    (report.get("provenance") or {}).get("evidence_sha256") or ""
                ),
                "request_sha256": identity["request_sha256"],
                "response_sha256": computed_response_sha256,
                "provider_id": response.provider_id,
                "model_id": response.model_id,
                "prompt_sha256": self.prompt_sha256,
                "schema_sha256": self.schema_sha256,
                "policy_sha256": self.policy_sha256,
                "provider_identity": {
                    "adapter_revision": identity["adapter_revision"],
                    "endpoint_sha256": identity["endpoint_sha256"],
                    "api_version": identity["api_version"],
                    "request_options_sha256": identity["request_options_sha256"],
                },
                "request_budget": {
                    "request_bytes": int(identity["request_bytes"]),
                    "request_tokens_estimate": int(identity["request_tokens"]),
                    "max_request_bytes": min(
                        self.config.ai_advisory_max_request_bytes,
                        int(self.policy["limits"]["max_request_bytes"]),
                    ),
                    "max_request_tokens": min(
                        self.config.ai_advisory_max_request_tokens,
                        int(self.policy["limits"]["max_request_tokens"]),
                    ),
                },
            },
        }
        record = self._record(
            task=task,
            identity=identity,
            projection=projection,
            status="accepted",
            response_sha256=computed_response_sha256,
            payload=payload,
            metrics={
                "schema_valid": True,
                "validator_accepted": True,
                "validator_reason_code": "",
                "cache_hit": False,
                "abstained": bool(normalized_advisory["abstained"]),
                "selected_finding_count": len(normalized_advisory["selected_finding_ids"]),
                "selected_relationship_count": len(normalized_advisory["selected_relationship_ids"]),
                "selected_action_count": len(normalized_advisory["ranked_action_ids"]),
                "shadow_candidate_count": len(shadow["candidates"]),
                "shadow_evidence_reference_count": len(evidence_refs),
                "request_bytes": int(identity["request_bytes"]),
                "request_tokens_estimate": int(identity["request_tokens"]),
                **provider_usage,
            },
        )
        renew_claim()
        completed = self.storage.complete_ai_advisory_job(
            job["job_id"],
            job["claim_owner"],
            job["claim_token"],
            record,
            completion_code="accepted",
        )
        if not completed:
            raise RuntimeError("AI advisory completion lost its claim")
        return "accepted"

    def process_once(
        self,
        *,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> int:
        if not self.config.enable_ai_advisory:
            return 0
        try:
            self.storage.initialize_ai_advisory_extension()
            # Reconcile the gap between canonical commit and best-effort
            # enqueue. Both operations are idempotent and queue bounded.
            self.storage.reconcile_ai_advisory_outbox(
                reconciliation_cutoff=(
                    self.config.ai_advisory_reconciliation_cutoff
                ),
                limit=self.config.ai_advisory_reconcile_batch_size,
                max_queue_records=self.config.ai_advisory_max_queue_records,
            )
            # Only optional AI rows are pruned. Canonical reports, sessions,
            # events, predictions, and deterministic artifacts are untouched.
            self.storage.prune_ai_advisories(
                self.config.ai_advisory_retention_days,
                keep_latest_per_session=False,
                max_records=self.config.ai_advisory_max_records,
                max_storage_bytes=self.config.ai_advisory_max_storage_bytes,
            )
        except Exception as exc:
            _safe_log(
                {
                    "service": "ai_advisory_worker",
                    "status": "extension_unavailable",
                    "error_code": "ai_extension_unavailable",
                    "error_type": "StorageError",
                    "timestamp": utc_now(),
                }
            )
            redact_exception_for_log(exc)
            return 0
        processed = 0
        for _ in range(self.config.ai_advisory_batch_size):
            if should_stop is not None and should_stop():
                break
            jobs = self.storage.claim_ai_advisory_jobs(
                self.worker_owner,
                1,
                self.config.ai_advisory_lease_seconds,
                self.config.ai_advisory_max_attempts,
            )
            if not jobs:
                break
            job = jobs[0]
            started = time.monotonic()
            with JobLeaseHeartbeat(self.storage, self.config, "ai_advisory", job) as heartbeat:
                try:
                    status = self._process_claim(
                        job,
                        renew_claim=lambda: heartbeat.check(renew=True),
                    )
                    processed += 1
                    _safe_log(
                        {
                            "service": "ai_advisory_worker",
                            "job_id": job["job_id"],
                            "status": status,
                            "attempts": job["attempts"],
                            "cache_hit": status == "cache_replayed",
                            "latency_ms": round((time.monotonic() - started) * 1000, 3),
                            "timestamp": utc_now(),
                        }
                    )
                except AIProviderUnavailable as exc:
                    transition = self.storage.fail_job(
                        "ai_advisory",
                        job["job_id"],
                        job["claim_owner"],
                        job["claim_token"],
                        "ai_provider_unavailable",
                        "RuntimeError",
                        True,
                        self.config.ai_advisory_max_attempts,
                        _retry_delay(self.config, int(job.get("attempts") or 1)),
                    )
                    _safe_log(
                        {
                            "service": "ai_advisory_worker",
                            "job_id": job["job_id"],
                            "status": transition,
                            "error_code": "ai_provider_unavailable",
                            "error_type": "RuntimeError",
                            "attempts": job["attempts"],
                            "latency_ms": round((time.monotonic() - started) * 1000, 3),
                            "timestamp": utc_now(),
                        }
                    )
                    del exc
                except Exception as exc:
                    retryable = not isinstance(exc, AIAdvisoryContractError)
                    error_code = (
                        "ai_job_invalid"
                        if isinstance(exc, AIAdvisoryContractError)
                        else "ai_advisory_failed"
                    )
                    error_type = "ValidationError" if isinstance(exc, AIAdvisoryContractError) else "Exception"
                    transition = self.storage.fail_job(
                        "ai_advisory",
                        job["job_id"],
                        job["claim_owner"],
                        job["claim_token"],
                        error_code,
                        error_type,
                        retryable,
                        self.config.ai_advisory_max_attempts,
                        _retry_delay(self.config, int(job.get("attempts") or 1)),
                    )
                    _safe_log(
                        {
                            "service": "ai_advisory_worker",
                            "job_id": job["job_id"],
                            "status": transition,
                            "error_code": error_code,
                            "error_type": error_type,
                            "attempts": job["attempts"],
                            "latency_ms": round((time.monotonic() - started) * 1000, 3),
                            "timestamp": utc_now(),
                        }
                    )
                    redact_exception_for_log(exc)
        return processed

    def run_forever(self, lifecycle: Optional[ServiceLifecycle] = None) -> None:
        control = lifecycle or ServiceLifecycle()
        with control.signal_handlers():
            while not control.stopping:
                self.process_once(should_stop=lambda: control.stopping)
                control.wait(self.config.ai_advisory_poll_seconds)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the non-authoritative AI advisory worker."
    )
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--once", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    worker = AIAdvisoryWorker(config)
    if args.once:
        print(
            json.dumps(
                {
                    "service": "ai_advisory_worker",
                    "processed": worker.process_once(),
                },
                sort_keys=True,
            )
        )
        return 0
    worker.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
