"""Background enrichment worker for cached, nonblocking external lookups."""

from __future__ import annotations

import argparse
import json
import time
from typing import Any, Callable, Dict, List, Optional

from production.utils.config import ProductionConfig
from production.enrichment.enrichment_providers import (
    EnrichmentProvider,
    ProviderResult,
    build_default_providers,
    merge_provider_results,
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
        self.storage = open_storage(config.database_url)
        self.providers = providers if providers is not None else build_default_providers(config)
        self.worker_owner = new_job_owner("enrichment")

    def _run_providers(self, observable_type: str, observable_value: str) -> List[ProviderResult]:
        results: List[ProviderResult] = []
        for provider in self.providers:
            if not provider.supports(observable_type):
                continue
            started_at = time.monotonic()
            try:
                result = provider.enrich(observable_type, observable_value)
                result.latency_ms = round(
                    max(time.monotonic() - started_at, 0.0) * 1000,
                    3,
                )
                results.append(result)
            except Exception as exc:
                results.append(
                    ProviderResult(
                        provider=provider.name,
                        status="error",
                        error=redact_exception_for_log(exc),
                        ttl_seconds=min(self.config.enrichment_ttl_seconds, 3600),
                        latency_ms=round(
                            max(time.monotonic() - started_at, 0.0) * 1000,
                            3,
                        ),
                    )
                )
        if not results:
            results.append(
                ProviderResult(
                    provider="none",
                    status="not_configured",
                    ttl_seconds=min(self.config.enrichment_ttl_seconds, 3600),
                )
            )
        return results

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
            with JobLeaseHeartbeat(self.storage, self.config, "enrichment", job) as heartbeat:
                try:
                    results = self._run_providers(observable_type, observable_value)
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
                    )
                    self.storage.save_enrichment_record(
                        observable_type,
                        observable_value,
                        payload,
                        provider_status,
                        expires_at=expires_at,
                    )
                    if any(result.status == "error" for result in results):
                        # Preserve per-provider status in the cache, but keep the
                        # durable job retryable instead of declaring a partial
                        # provider outage to be complete enrichment success.
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
