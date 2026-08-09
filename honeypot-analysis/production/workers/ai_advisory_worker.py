"""Asynchronous non-authoritative AI advisory outbox worker."""

from __future__ import annotations

import argparse
import json
import re
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
from production.ai_advisory.projection import build_ai_advisory_projection
from production.ai_advisory.provider import (
    AIAdvisoryProvider,
    AIProviderUnavailable,
    build_ai_advisory_provider,
)
from production.ai_advisory.rendering import render_validated_advisory
from production.storage import open_storage
from production.utils.config import ProductionConfig
from production.utils.sensitive_data import redact_exception_for_log
from production.utils.serialization import stable_id, stable_json, utc_now
from production.utils.service_lifecycle import ServiceLifecycle
from production.workers.job_lifecycle import JobLeaseHeartbeat, new_job_owner


TASK_KEYS = {"schema_version", "report_id", "session_id", "assessment_id"}
ZERO_SHA256 = "0" * 64
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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
        self.storage = storage or open_storage(config.database_url)
        self.policy, self.policy_sha256, self.policy_path = (
            load_ai_advisory_policy(config.ai_advisory_policy_path)
        )
        self.provider = provider or build_ai_advisory_provider(config)
        self.prompt_sha256 = sha256_json(self.policy["prompt_contract"])
        self.response_schema = provider_output_json_schema(self.policy)
        self.schema_sha256 = contract_schema_sha256(self.policy)
        self.worker_owner = new_job_owner("ai-advisory")

    def _validate_task(self, job: Mapping[str, Any]) -> Dict[str, str]:
        task = job.get("task")
        if not isinstance(task, Mapping) or set(task) != TASK_KEYS:
            raise AIAdvisoryContractError("AI advisory task contract is invalid")
        if task.get("schema_version") != "ai_advisory_task.v1":
            raise AIAdvisoryContractError("AI advisory task schema is invalid")
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
        request_sha256 = sha256_json(
            {
                "projection": projection,
                "provider_identity": provider_identity,
                "prompt_sha256": self.prompt_sha256,
                "schema_sha256": self.schema_sha256,
                "policy_sha256": self.policy_sha256,
                "request_bytes": request_bytes,
                "request_tokens": request_tokens,
                "request_limits": {
                    "max_bytes": min(
                        self.config.ai_advisory_max_request_bytes,
                        int(self.policy["limits"]["max_request_bytes"]),
                    ),
                    "max_tokens": min(
                        self.config.ai_advisory_max_request_tokens,
                        int(self.policy["limits"]["max_request_tokens"]),
                    ),
                },
            }
        )
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
            "policy_sha256": self.policy_sha256,
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
        return {
            "advisory_id": row["advisory_id"],
            "cache_key": row["cache_key"],
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
            "metrics": row["metrics"],
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

    def _process_claim(
        self,
        job: Mapping[str, Any],
        *,
        renew_claim: Callable[[], None],
    ) -> str:
        task = self._validate_task(job)
        report_row = self.storage.get_report_by_id(task["report_id"])
        if not report_row or not isinstance(report_row.get("payload"), Mapping):
            raise AIAdvisoryContractError("persisted canonical report is unavailable")
        report = report_row["payload"]
        if (
            str(report.get("assessment_id") or "") != task["assessment_id"]
            or str(report_row.get("session_id") or "") != task["session_id"]
        ):
            raise AIAdvisoryContractError("persisted report identity does not match task")
        projection = build_ai_advisory_projection(
            report,
            policy=self.policy,
            policy_sha256=self.policy_sha256,
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

        response = self.provider.generate(
            projection,
            prompt_contract=self.policy["prompt_contract"],
            response_schema=self.response_schema,
            schema_sha256=self.schema_sha256,
            policy_sha256=self.policy_sha256,
            timeout_seconds=self.config.ai_advisory_timeout_seconds,
            max_response_bytes=min(
                self.config.ai_advisory_max_response_bytes,
                int(self.policy["limits"]["max_response_bytes"]),
            ),
        )
        try:
            response_bytes = stable_json(response.structured_output).encode("utf-8")
            response_limit = min(
                self.config.ai_advisory_max_response_bytes,
                int(self.policy["limits"]["max_response_bytes"]),
            )
            if len(response_bytes) > response_limit:
                raise AIAdvisoryContractError("provider response exceeds the configured limit")
            if response.response_sha256 != sha256_json(response.structured_output):
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
                policy_sha256=self.policy_sha256,
            )
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
                response_sha256=response.response_sha256,
                payload=payload,
                metrics={
                    "schema_valid": False,
                    "validator_accepted": False,
                    "validator_reason_code": exc.code,
                    "cache_hit": False,
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
                "evidence_sha256": projection["evidence_sha256"],
                "request_sha256": identity["request_sha256"],
                "response_sha256": response.response_sha256,
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
            response_sha256=response.response_sha256,
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
        # Retain only the bounded advisory extension.  This is deliberately
        # outside canonical report retention and never deletes sessions,
        # events, reports, predictions, or historical compatibility records.
        self.storage.prune_ai_advisories(
            self.config.ai_advisory_retention_days,
            keep_latest_per_session=True,
        )
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
                        False,
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
