"""Background enrichment worker for cached, nonblocking external lookups."""

from __future__ import annotations

import argparse
import json
import time
from typing import Any, Dict, List, Optional

from production.utils.config import ProductionConfig
from production.enrichment.enrichment_providers import (
    EnrichmentProvider,
    ProviderResult,
    build_default_providers,
    merge_provider_results,
)
from production.utils.sensitive_data import redact_exception_for_log
from production.utils.serialization import utc_now
from production.storage import open_storage


class EnrichmentWorker:
    """Process queued enrichment jobs and write normalized cache records."""

    def __init__(self, config: ProductionConfig, providers: Optional[List[EnrichmentProvider]] = None) -> None:
        self.config = config
        self.storage = open_storage(config.database_url)
        self.providers = providers if providers is not None else build_default_providers(config)

    def _run_providers(self, observable_type: str, observable_value: str) -> List[ProviderResult]:
        results: List[ProviderResult] = []
        for provider in self.providers:
            if not provider.supports(observable_type):
                continue
            try:
                results.append(provider.enrich(observable_type, observable_value))
            except Exception as exc:
                results.append(
                    ProviderResult(
                        provider=provider.name,
                        status="error",
                        error=redact_exception_for_log(exc),
                        ttl_seconds=min(self.config.enrichment_ttl_seconds, 3600),
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

    def process_once(self) -> int:
        jobs = self.storage.claim_enrichment_jobs(self.config.enrichment_batch_size)
        processed = 0
        for job in jobs:
            observable_type = job["observable_type"]
            observable_value = job["observable_value"]
            try:
                results = self._run_providers(observable_type, observable_value)
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
                self.storage.complete_enrichment_job(job["job_id"])
                processed += 1
            except Exception as exc:
                retry = int(job["attempts"]) < self.config.enrichment_max_attempts
                self.storage.fail_enrichment_job(
                    job["job_id"],
                    redact_exception_for_log(exc),
                    retry=retry,
                    retry_seconds=self.config.enrichment_retry_seconds,
                )
                print(
                    json.dumps(
                        {
                            "service": "enrichment_worker",
                            "job_id": job["job_id"],
                            "status": "retry" if retry else "failed",
                            "error": redact_exception_for_log(exc),
                            "timestamp": utc_now(),
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
        return processed

    def run_forever(self) -> None:
        while True:
            processed = self.process_once()
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
            time.sleep(self.config.worker_poll_seconds)


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
