"""Background enrichment worker for cached, nonblocking external lookups."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import time
from typing import Any, Callable, Dict, List, Optional

from production.policies.data_lifecycle_policy import load_data_lifecycle_policy
from production.utils.config import ProductionConfig
from production.enrichment.enrichment_providers import (
    EnrichmentProvider,
    ProviderBudgetError,
    ProviderResult,
    build_default_providers,
    merge_provider_results,
)
from production.enrichment.enrichment_cache import (
    SOURCE_IP_CACHE_PROVIDERS,
    SourceIPCacheService,
    SourceIPCacheUnavailable,
)
from production.enrichment.external_ti_contract import (
    ExternalTIMetrics,
    ProviderPacingBudget,
    SOURCE_IP_ENRICHMENT_MODE,
    SOURCE_IP_PROVIDER_NAMES,
    evaluate_outbound_sighting,
    load_source_ip_governance_amendment,
    parse_source_ip_cutoff_utc,
    provider_activation_gate,
    provider_config,
    provider_config_identity,
)
from production.enrichment.external_ti_proof_guard import (
    ExternalTIProductionGuard,
    ExternalTIProofGuard,
    PROOF_GUARD_MODE_REAL,
)
from production.utils.sensitive_data import redact_exception_for_log
from production.utils.serialization import utc_now
from production.utils.service_lifecycle import ServiceLifecycle
from production.storage import open_storage
from production.workers.job_lifecycle import (
    JobLeaseHeartbeat,
    job_failure_identity,
    job_retry_delay,
    new_job_owner,
)


class EnrichmentWorker:
    """Process queued enrichment jobs and write normalized cache records."""

    def __init__(self, config: ProductionConfig, providers: Optional[List[EnrichmentProvider]] = None) -> None:
        self.config = config
        self.storage = open_storage(config.database_settings())
        self.source_ip_cache = SourceIPCacheService(self.storage)
        self.providers = providers if providers is not None else build_default_providers(config)
        self.data_lifecycle_policy = load_data_lifecycle_policy(
            config.data_lifecycle_policy_path
        )
        self.worker_owner = new_job_owner("enrichment")
        self.pacing = ProviderPacingBudget()
        self.metrics = ExternalTIMetrics()
        self.source_ip_mode = str(
            getattr(config, "source_ip_enrichment_mode", "disabled") or "disabled"
        ).strip()
        self.source_ip_cutoff_utc = None
        self.source_ip_governance = None
        self.proof_guard = None
        source_configs = getattr(config, "external_ti_provider_configs", {}) or {}
        source_ip_requested = self.source_ip_mode == SOURCE_IP_ENRICHMENT_MODE or any(
            str(name).strip().lower() in SOURCE_IP_PROVIDER_NAMES
            and "ip"
            in {
                str(item).strip().lower()
                for item in value.get("observable_types", []) or []
            }
            and "source_ip"
            in {
                str(item).strip().lower()
                for item in value.get("observable_roles", []) or []
            }
            and (
                str(name).strip().lower() in {
                    str(item).strip().lower()
                    for item in getattr(config, "external_ti_provider_allowlist", []) or []
                }
                or bool(value.get("enabled"))
            )
            for name, value in source_configs.items()
            if isinstance(value, dict)
        )
        if source_ip_requested:
            if self.source_ip_mode != SOURCE_IP_ENRICHMENT_MODE:
                raise ValueError("source-IP worker requires NEW_ELIGIBLE_SIGHTINGS_ONLY mode")
            self.source_ip_cutoff_utc = parse_source_ip_cutoff_utc(
                getattr(config, "source_ip_enrichment_not_before_utc", "")
            )
            self.source_ip_governance = load_source_ip_governance_amendment(
                getattr(config, "source_ip_governance_path", ""),
                expected_sha256=getattr(
                    config,
                    "source_ip_governance_sha256",
                    "",
                ),
            )
            proof_mode = str(
                getattr(config, "external_ti_proof_guard_mode", "DISABLED") or "DISABLED"
            ).strip().upper()
            proof_campaign = str(
                getattr(config, "external_ti_proof_campaign_id", "") or ""
            ).strip()
            if proof_mode != PROOF_GUARD_MODE_REAL or not proof_campaign:
                raise ValueError("source-IP worker requires REAL_PROOF durable guard")
            if self.source_ip_governance.continuous_processing:
                self.proof_guard = ExternalTIProductionGuard(
                    self.storage,
                    proof_campaign,
                    proof_mode,
                    max_daily_targets=(
                        self.source_ip_governance.max_distinct_source_ips_per_utc_day
                    ),
                )
            else:
                self.proof_guard = ExternalTIProofGuard(
                    self.storage,
                    proof_campaign,
                    proof_mode,
                )

    @staticmethod
    def _proof_result_class(status: str) -> str:
        normalized = str(status or "").strip().lower()
        return {
            "ok": "DATA",
            "not_found": "NO_DATA",
            "auth_disabled": "AUTH_FAILED",
            "rate_limited": "RATE_LIMITED",
            "malformed_response": "NORMALIZATION_FAILED",
        }.get(normalized, "REQUEST_FAILED")

    def _provider_sighting(
        self,
        observable_type: str,
        observable_value: str,
        *,
        sighting: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if isinstance(sighting, dict):
            return dict(sighting)
        storage = getattr(self, "storage", None)
        loader = getattr(storage, "list_observable_sightings", None)
        if loader is not None:
            try:
                rows = loader(observable_type, observable_value, limit=20)
            except Exception:
                rows = []
            for row in rows or []:
                if isinstance(row, dict):
                    decision = evaluate_outbound_sighting(
                        row,
                        source_ip_governance=self.source_ip_governance,
                        source_ip_cutoff_utc=self.source_ip_cutoff_utc,
                        source_ip_mode=self.source_ip_mode,
                    )
                    if decision.eligible:
                        return dict(row)
        return {
            "observable_type": observable_type,
            "observable_value": observable_value,
        }

    @staticmethod
    def _credential_present(provider: EnrichmentProvider) -> bool:
        if hasattr(provider, "credential_present"):
            return bool(getattr(provider, "credential_present"))
        if provider.name == "censys":
            return bool(
                getattr(provider, "platform_token", "")
                or (
                    getattr(provider, "api_id", "")
                    and getattr(provider, "api_key", "")
                )
            )
        return bool(getattr(provider, "api_key", ""))

    @staticmethod
    def _provider_result_metadata(
        result: ProviderResult,
        provider: EnrichmentProvider,
        settings: Dict[str, Any],
        *,
        budget_consumed: int = 0,
    ) -> ProviderResult:
        result.provider = str(result.provider or provider.name).strip().lower()
        result.endpoint_id = str(
            result.endpoint_id or settings.get("endpoint_id") or ""
        )
        result.provider_mode = str(
            result.provider_mode or settings.get("mode") or "lookup"
        )
        result.normalizer_identity = str(
            result.normalizer_identity
            or settings.get("normalizer_identity")
            or "external_ti_evidence.v1"
        )
        result.privacy_policy_identity = str(
            result.privacy_policy_identity
            or settings.get("policy_identity")
            or "external_ti_non_ip.v1"
        )
        result.provider_config_identity = str(
            result.provider_config_identity
            or settings.get("provider_config_identity")
            or provider_config_identity(provider.name, settings)
        )
        if result.attempt_count <= 0 and result.status in {
            "ok",
            "not_found",
            "error",
            "temporary_error",
            "permanent_error",
            "rate_limited",
            "malformed_response",
        }:
            result.attempt_count = 1
        result.budget_consumed = max(int(result.budget_consumed), int(budget_consumed))
        return result

    @staticmethod
    def _fresh_cached_status(status: Any, *, expected_config_identity: str = "") -> bool:
        if not isinstance(status, dict) or str(status.get("status") or "") not in {
            "ok",
            "not_found",
            "cached",
            "auth_disabled",
        }:
            return False
        recorded_identity = str(status.get("provider_config_identity") or "")
        if expected_config_identity and recorded_identity and recorded_identity != expected_config_identity:
            return False
        expires = str(status.get("expires_at") or "")
        if not expires:
            return False
        try:
            from datetime import datetime, timezone

            parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed > datetime.now(timezone.utc)
        except (TypeError, ValueError):
            return False

    def _run_providers(
        self,
        observable_type: str,
        observable_value: str,
        *,
        sighting: Optional[Dict[str, Any]] = None,
        existing_record: Optional[Dict[str, Any]] = None,
    ) -> List[ProviderResult]:
        supported = [
            provider for provider in self.providers if provider.supports(observable_type)
        ]
        profile = getattr(self.config, "external_enrichment_profile", "disabled")
        provider_configs = getattr(self.config, "external_ti_provider_configs", {}) or {}
        provider_sighting = self._provider_sighting(
            observable_type,
            observable_value,
            sighting=sighting,
        )
        existing_status = (existing_record or {}).get("provider_status") or {}
        selected: List[EnrichmentProvider] = []
        blocked: List[ProviderResult] = []
        cached: List[ProviderResult] = []
        for provider in supported:
            if not getattr(provider, "external", False):
                selected.append(provider)
                continue
            settings = provider_config(provider.name, provider_configs.get(provider.name))
            expected_identity = provider_config_identity(provider.name, settings)
            if observable_type == "ip" and provider.name in SOURCE_IP_CACHE_PROVIDERS:
                try:
                    source_cache_entry = self.source_ip_cache.lookup(
                        provider.name,
                        observable_value,
                        expected_config_identity=expected_identity,
                    )
                except SourceIPCacheUnavailable:
                    # A cache read failure must suppress new external traffic.
                    # ``disabled`` is intentional here: it is not a provider
                    # attempt and therefore must not become a cached failure or
                    # an automatic retry/request loop.
                    blocked.append(
                        self._provider_result_metadata(
                            ProviderResult(
                                provider.name,
                                "disabled",
                                data={"gate": "source_ip_cache_unavailable"},
                                ttl_seconds=min(
                                    getattr(self.config, "enrichment_ttl_seconds", 86400),
                                    3600,
                                ),
                            ),
                            provider,
                            settings,
                        )
                    )
                    if hasattr(self, "metrics"):
                        self.metrics.increment("source_ip_cache_unavailable")
                    continue
                if source_cache_entry is not None:
                    cached.append(
                        self._provider_result_metadata(
                            SourceIPCacheService.cached_result(source_cache_entry),
                            provider,
                            settings,
                        )
                    )
                    if hasattr(self, "metrics"):
                        self.metrics.increment("source_ip_cache_hit")
                    continue
            if self._fresh_cached_status(
                existing_status.get(provider.name),
                expected_config_identity=expected_identity,
            ):
                cached.append(
                    self._provider_result_metadata(
                        ProviderResult(
                            provider.name,
                            "cached",
                            ttl_seconds=getattr(self.config, "enrichment_ttl_seconds", 86400),
                            fetched_at=str(existing_status[provider.name].get("fetched_at") or utc_now()),
                        ),
                        provider,
                        settings,
                    )
                )
                self.metrics.increment("cache_hit") if hasattr(self, "metrics") else None
                continue
            decision = provider_activation_gate(
                provider=provider.name,
                config=self.config,
                provider_config_value=settings,
                sighting=provider_sighting,
                credential_present=self._credential_present(provider),
                credential_required=bool(getattr(provider, "requires_credential", True)),
                source_ip_governance=self.source_ip_governance,
                source_ip_cutoff_utc=self.source_ip_cutoff_utc,
                source_ip_mode=self.source_ip_mode,
            )
            if not decision.eligible:
                blocked.append(
                    self._provider_result_metadata(
                        ProviderResult(
                            provider.name,
                            "policy_prohibited"
                            if decision.code == "unknown_provider"
                            or (
                                decision.code.startswith("source_ip_")
                                and observable_type == "ip"
                            )
                            else "disabled",
                            data={"gate": decision.code},
                            ttl_seconds=min(getattr(self.config, "enrichment_ttl_seconds", 86400), 3600),
                        ),
                        provider,
                        settings,
                    )
                )
                if hasattr(self, "metrics"):
                    self.metrics.increment(f"gate_{decision.code}")
                continue
            selected.append(provider)

        def run_provider(provider: EnrichmentProvider) -> ProviderResult:
            started_at = time.monotonic()
            settings = provider_config(provider.name, provider_configs.get(provider.name))
            proof_claimed = False
            if observable_type == "ip" and provider.name in SOURCE_IP_CACHE_PROVIDERS:
                if self.proof_guard is None:
                    return self._provider_result_metadata(
                        ProviderResult(
                            provider.name,
                            "policy_prohibited",
                            data={"gate": "proof_guard_required"},
                            ttl_seconds=min(
                                getattr(self.config, "enrichment_ttl_seconds", 86400),
                                3600,
                            ),
                        ),
                        provider,
                        settings,
                    )
                observed_at = str(provider_sighting.get("timestamp") or utc_now())
                cutoff_text = str(
                    getattr(self.config, "source_ip_enrichment_not_before_utc", "")
                    or (self.source_ip_cutoff_utc.isoformat() if self.source_ip_cutoff_utc else "")
                )
                claim = self.proof_guard.claim_for_provider(
                    provider.name,
                    observable_value,
                    cutoff_utc=cutoff_text,
                    first_observed_at=observed_at,
                )
                if not claim.allowed:
                    if hasattr(self, "metrics"):
                        self.metrics.increment(f"proof_guard_{claim.code.lower()}")
                    return self._provider_result_metadata(
                        ProviderResult(
                            provider.name,
                            "policy_prohibited",
                            data={"gate": claim.code},
                            ttl_seconds=min(
                                getattr(self.config, "enrichment_ttl_seconds", 86400),
                                3600,
                            ),
                        ),
                        provider,
                        settings,
                    )
                proof_claimed = True
            budget = getattr(self, "pacing", None)
            budget_consumed = 0
            attempt_reserver = getattr(provider, "attempt_reserver", None)
            reserved_attempts = 0

            def reserve_attempt() -> Any:
                nonlocal reserved_attempts
                budget_decision = budget.reserve(
                    provider.name,
                    minute_limit=int(settings.get("minute_limit") or 0),
                    daily_budget=int(settings.get("daily_budget") or 0),
                )
                if budget_decision.allowed:
                    reserved_attempts += 1
                return budget_decision

            if getattr(provider, "external", False) and budget is not None:
                if hasattr(provider, "_json_get") and hasattr(provider, "attempt_reserver"):
                    # Built-in HTTP adapters reserve once for every actual
                    # retry attempt, including Retry-After governed retries.
                    provider.attempt_reserver = reserve_attempt
                else:
                    budget_decision = reserve_attempt()
                    if not budget_decision.allowed:
                        if hasattr(self, "metrics"):
                            self.metrics.increment(f"budget_{budget_decision.status}")
                        return self._provider_result_metadata(
                            ProviderResult(
                                provider.name,
                                budget_decision.status,
                                ttl_seconds=min(getattr(self.config, "enrichment_ttl_seconds", 86400), 3600),
                                next_eligible_at=budget_decision.next_eligible_at,
                            ),
                            provider,
                            settings,
                        )
                    budget_consumed = 1
            try:
                result = provider.enrich(observable_type, observable_value)
                result.latency_ms = round(
                    max(time.monotonic() - started_at, 0.0) * 1000,
                    3,
                )
                budget_consumed = max(budget_consumed, reserved_attempts)
                if result.status == "rate_limited" and budget is not None and result.retry_after_seconds is not None:
                    result.next_eligible_at = budget.defer(
                        provider.name,
                        result.retry_after_seconds,
                    )
                if proof_claimed:
                    try:
                        self.proof_guard.complete_provider(
                            provider.name,
                            self._proof_result_class(result.status),
                            http_status=result.http_status,
                        )
                    except Exception:
                        if hasattr(self, "metrics"):
                            self.metrics.increment("proof_guard_completion_failed")
                return self._provider_result_metadata(
                    result,
                    provider,
                    settings,
                    budget_consumed=budget_consumed,
                )
            except ProviderBudgetError as exc:
                decision = exc.decision
                if hasattr(self, "metrics"):
                    self.metrics.increment(f"budget_{getattr(decision, 'status', 'exhausted')}")
                if proof_claimed:
                    try:
                        self.proof_guard.complete_provider(
                            provider.name,
                            "REQUEST_FAILED",
                        )
                    except Exception:
                        if hasattr(self, "metrics"):
                            self.metrics.increment("proof_guard_completion_failed")
                return self._provider_result_metadata(
                    ProviderResult(
                        provider=provider.name,
                        status=str(getattr(decision, "status", "budget_exhausted")),
                        ttl_seconds=min(getattr(self.config, "enrichment_ttl_seconds", 86400), 3600),
                        next_eligible_at=getattr(decision, "next_eligible_at", None),
                        attempt_count=reserved_attempts,
                        budget_consumed=reserved_attempts,
                    ),
                    provider,
                    settings,
                )
            except Exception as exc:
                budget_consumed = max(budget_consumed, reserved_attempts)
                if proof_claimed:
                    try:
                        self.proof_guard.complete_provider(
                            provider.name,
                            "REQUEST_FAILED",
                        )
                    except Exception:
                        if hasattr(self, "metrics"):
                            self.metrics.increment("proof_guard_completion_failed")
                return self._provider_result_metadata(
                    ProviderResult(
                        provider=provider.name,
                        # Compatibility alias for providers outside the built-in
                        # adapters, whose exception type cannot be classified here.
                        status="error",
                        error=redact_exception_for_log(exc),
                        ttl_seconds=min(getattr(self.config, "enrichment_ttl_seconds", 86400), 3600),
                        latency_ms=round(
                            max(time.monotonic() - started_at, 0.0) * 1000,
                            3,
                        ),
                    ),
                    provider,
                    settings,
                    budget_consumed=budget_consumed,
                )
            finally:
                if (
                    hasattr(provider, "attempt_reserver")
                    and getattr(provider, "attempt_reserver", None) is reserve_attempt
                ):
                    provider.attempt_reserver = attempt_reserver

        results: List[ProviderResult] = []
        if selected:
            max_workers = min(
                len(selected),
                max(int(getattr(self.config, "enrichment_provider_workers", 4)), 1),
            )
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers,
                thread_name_prefix="enrichment-provider",
            ) as executor:
                # executor.map preserves configured provider order even though
                # requests execute concurrently.
                results = list(executor.map(run_provider, selected))
        results = cached + blocked + results
        if not results:
            results.append(
                ProviderResult(
                    provider="none",
                    status="not_configured",
                    ttl_seconds=min(getattr(self.config, "enrichment_ttl_seconds", 86400), 3600),
                )
            )
        return results

    def _persist_source_ip_cache_results(
        self,
        observable_type: str,
        observable_value: str,
        results: List[ProviderResult],
    ) -> None:
        """Persist only actual source-provider outcomes in the isolated cache."""

        if observable_type != "ip" or self.source_ip_governance is None:
            return
        provider_configs = getattr(self.config, "external_ti_provider_configs", {}) or {}
        for result in results:
            provider_name = str(result.provider or "").strip().lower()
            if (
                provider_name not in SOURCE_IP_CACHE_PROVIDERS
                or result.status in {"cached", "disabled", "policy_prohibited", "budget_exhausted"}
                or int(getattr(result, "attempt_count", 0) or 0) <= 0
            ):
                continue
            settings = provider_config(
                provider_name,
                provider_configs.get(provider_name),
            )
            # The service strips error text and raw response data before this
            # write.  A backend failure raises a fixed, secret-free exception
            # and must not turn an optional ETI persistence problem into a
            # canonical job failure.  The cache lookup is fail-closed on the
            # next attempt, so this also cannot create an unbounded provider
            # retry loop when the backend is unavailable.
            try:
                self.source_ip_cache.store_result(
                    provider_name,
                    observable_value,
                    result,
                    settings,
                    privacy_policy_version=self.source_ip_governance.version,
                )
            except SourceIPCacheUnavailable:
                if hasattr(self, "metrics"):
                    self.metrics.increment("source_ip_cache_unavailable")

    @staticmethod
    def _job_sighting(job: Dict[str, Any]) -> Dict[str, Any]:
        payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
        sighting = {
            "observable_type": job.get("observable_type", ""),
            "observable_value": job.get("observable_value", ""),
            "session_id": job.get("session_id") or payload.get("session_id", ""),
        }
        for key in (
            "role",
            "source",
            "sighting_id",
            "observable_id",
            "event_id",
            "eventid",
            "sensor_id",
            "timestamp",
        ):
            if payload.get(key) not in (None, ""):
                sighting[key] = payload[key]
        nested_payload = payload.get("payload")
        if isinstance(nested_payload, dict):
            sighting["payload"] = dict(nested_payload)
        elif isinstance(payload.get("metadata"), dict):
            sighting["payload"] = {"metadata": dict(payload["metadata"])}
        return sighting

    def process_once(
        self,
        *,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> int:
        processed = 0
        for _ in range(self.config.enrichment_batch_size):
            if should_stop is not None and should_stop():
                break
            jobs = self.storage.claim_enrichment_jobs(
                self.worker_owner,
                1,
                self.config.job_lease_seconds,
                self.config.enrichment_max_attempts,
            )
            if not jobs:
                break
            job = jobs[0]
            if should_stop is not None and should_stop():
                self.storage.release_job_claim(
                    "enrichment",
                    job["job_id"],
                    job["claim_owner"],
                    job["claim_token"],
                )
                break
            observable_type = job["observable_type"]
            observable_value = job["observable_value"]
            job_sighting = self._job_sighting(job)
            with JobLeaseHeartbeat(self.storage, self.config, "enrichment", job) as heartbeat:
                try:
                    existing = self.storage.get_enrichment_record(
                        observable_type,
                        observable_value,
                        allow_stale=True,
                    )
                    results = self._run_providers(
                        observable_type,
                        observable_value,
                        sighting=job_sighting,
                        existing_record=existing,
                    )
                    self._persist_source_ip_cache_results(
                        observable_type,
                        observable_value,
                        results,
                    )
                    print(
                        json.dumps(
                            {
                                "service": "enrichment_worker",
                                "job_id": job["job_id"],
                                "correlation_id": job["job_id"],
                                "provider_results": [
                                    {
                                        "provider": result.provider,
                                        "status": result.status,
                                        "latency_ms": result.latency_ms,
                                    }
                                    for result in results
                                ],
                                "timestamp": utc_now(),
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                    payload, provider_status, expires_at = merge_provider_results(
                        observable_type,
                        observable_value,
                        results,
                        default_ttl_seconds=self.config.enrichment_ttl_seconds,
                        existing_payload=(existing or {}).get("payload"),
                        existing_provider_status=(existing or {}).get("provider_status"),
                    )
                    payload["enrichment_policy"] = {
                        "schema_version": "external_ti_enrichment_policy.v1",
                        "external_profile": self.config.external_enrichment_profile,
                        "external_ti_enabled": bool(
                            getattr(self.config, "external_ti_enabled", False)
                        ),
                        "provider_allowlist": sorted(
                            str(item).strip().lower()
                            for item in getattr(
                                self.config, "external_ti_provider_allowlist", []
                            )
                        ),
                        "policy_identity": getattr(
                            self.config,
                            "external_ti_policy_identity",
                            "external_ti_non_ip.v1",
                        ),
                        "normalizer_identity": getattr(
                            self.config,
                            "external_ti_normalizer_identity",
                            "external_ti_evidence.v1",
                        ),
                        "data_lifecycle_policy_id": self.data_lifecycle_policy.policy_id,
                        "data_lifecycle_policy_version": self.data_lifecycle_policy.version,
                        "data_lifecycle_policy_sha256": self.data_lifecycle_policy.sha256,
                        "source_ip_external_sharing_allowed": (
                            self.data_lifecycle_policy.document["privacy"][
                                "source_ip_external_sharing_allowed"
                            ]
                            is True
                        ),
                        "source_ip_enrichment_mode": self.source_ip_mode,
                        "source_ip_cutoff_timestamp_field": "timestamp",
                        "source_ip_enrichment_not_before_utc": (
                            self.source_ip_cutoff_utc.isoformat()
                            if self.source_ip_cutoff_utc is not None
                            else ""
                        ),
                        "source_ip_governance_policy_id": getattr(
                            self.source_ip_governance, "policy_id", ""
                        ),
                        "source_ip_governance_version": getattr(
                            self.source_ip_governance, "version", ""
                        ),
                        "source_ip_governance_sha256": getattr(
                            self.source_ip_governance, "sha256", ""
                        ),
                        "authority": "non_authoritative_context_only",
                    }
                    # The reviewed source-IP amendment permits bounded local
                    # campaign receipts but explicitly prohibits a canonical
                    # MongoDB enrichment-record write.  Keep provider output
                    # in memory for this job only; a separately authorized
                    # bounded preflight owns its local receipt persistence.
                    source_ip_record_write_prohibited = (
                        observable_type == "ip"
                        and self.source_ip_governance is not None
                        and self.source_ip_governance.canonical_mongodb_enrichment_record_write
                        is False
                    )
                    if not source_ip_record_write_prohibited:
                        self.storage.save_enrichment_record(
                            observable_type,
                            observable_value,
                            payload,
                            provider_status,
                            expires_at=expires_at,
                        )
                    if any(
                        result.status in {
                            "error",
                            "temporary_error",
                            "rate_limited",
                            "budget_exhausted",
                        }
                        for result in results
                    ):
                        # Preserve each provider's status in the cache, but keep
                        # only the durable job retryable.  A fresh successful
                        # provider subrecord is skipped on the next attempt.
                        raise ConnectionError("one or more enrichment providers failed")
                    heartbeat.check(renew=True)
                    completed = self.storage.complete_enrichment_job(
                        job["job_id"],
                        job["claim_owner"],
                        job["claim_token"],
                    )
                    processed += int(completed)
                except Exception as exc:
                    error_code, error_type, retryable = job_failure_identity(
                        "enrichment", exc
                    )
                    status = self.storage.fail_enrichment_job(
                        job["job_id"],
                        job["claim_owner"],
                        job["claim_token"],
                        error_code,
                        error_type,
                        retryable,
                        self.config.enrichment_max_attempts,
                        job_retry_delay(self.config, int(job.get("attempts") or 1)),
                    )
                    print(
                        json.dumps(
                            {
                                "service": "enrichment_worker",
                                "job_id": job["job_id"],
                                "correlation_id": job["job_id"],
                                "status": status,
                                "error": redact_exception_for_log(exc),
                                "timestamp": utc_now(),
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
        return processed

    def run_forever(self, lifecycle: Optional[ServiceLifecycle] = None) -> None:
        control = lifecycle or ServiceLifecycle()
        with control.signal_handlers():
            while not control.stopping:
                processed = self.process_once(should_stop=lambda: control.stopping)
                if processed:
                    print(
                        json.dumps(
                            {
                                "service": "enrichment_worker",
                                "processed": processed,
                                "timestamp": utc_now(),
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                control.wait(self.config.worker_poll_seconds)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the background enrichment worker.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--once", action="store_true", help="Process one enrichment batch and exit.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    worker = EnrichmentWorker(config)
    if args.once:
        processed = worker.process_once()
        print(json.dumps({"service": "enrichment_worker", "processed": processed}, sort_keys=True))
        return 0
    worker.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
