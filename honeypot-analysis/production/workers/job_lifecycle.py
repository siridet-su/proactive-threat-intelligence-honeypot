"""Shared lease heartbeat and stable failure policy for durable job workers."""

from __future__ import annotations

import threading
import uuid
from typing import Any, Dict, Optional

from production.storage.contract import EVENT_FAILURE_TYPES


class JobLeaseLost(RuntimeError):
    """Raised when a worker no longer owns its durable job claim."""


def new_job_owner(queue: str) -> str:
    return f"{queue}-worker:{uuid.uuid4()}"


def job_retry_delay(config: Any, attempts: int) -> float:
    exponent = min(max(int(attempts) - 1, 0), 31)
    return min(
        float(config.job_retry_max_seconds),
        float(config.job_retry_base_seconds) * (2**exponent),
    )


def job_failure_identity(queue: str, exc: Exception) -> tuple[str, str, bool]:
    if isinstance(exc, JobLeaseLost):
        return "job_processing_failed", "LeaseExpired", True
    if isinstance(exc, (TypeError, ValueError)):
        return "job_invalid", "ValidationError", False
    error_type = type(exc).__name__
    if error_type not in EVENT_FAILURE_TYPES:
        error_type = "Exception"
    queue_code = {
        "analysis": "analysis_failed",
        "enrichment": "enrichment_failed",
        "threat_hunt": "threat_hunt_failed",
    }
    return queue_code.get(queue, "job_processing_failed"), error_type, True


class JobLeaseHeartbeat:
    """Renew one job lease while its blocking or asynchronous work runs."""

    def __init__(
        self,
        storage: Any,
        config: Any,
        queue: str,
        job: Dict[str, Any],
    ) -> None:
        self.storage = storage
        self.config = config
        self.queue = queue
        self.job = job
        self._stop = threading.Event()
        self._lost = False
        self._thread = threading.Thread(
            target=self._run,
            name=f"{queue}-job-heartbeat",
            daemon=True,
        )

    def __enter__(self) -> "JobLeaseHeartbeat":
        self._thread.start()
        return self

    def _setting(self, suffix: str) -> float:
        queue_name = self.queue.replace("-", "_")
        specific = f"{queue_name}_{suffix}"
        common = f"job_{suffix}"
        return float(getattr(self.config, specific, getattr(self.config, common)))

    def __exit__(self, *_args: Any) -> None:
        self._stop.set()
        self._thread.join(timeout=max(1.0, self._setting("lease_heartbeat_seconds")))

    def _renew(self) -> None:
        renewed = self.storage.renew_job_claim(
            self.queue,
            self.job["job_id"],
            self.job["claim_owner"],
            self.job["claim_token"],
            self._setting("lease_seconds"),
        )
        if not renewed:
            raise JobLeaseLost("durable job lease was lost")

    def _run(self) -> None:
        interval = self._setting("lease_heartbeat_seconds")
        while not self._stop.wait(interval):
            try:
                self._renew()
            except Exception:
                self._lost = True
                return

    def check(self, *, renew: bool = False) -> None:
        if self._lost:
            raise JobLeaseLost("durable job lease was lost")
        if renew:
            self._renew()
        if self._lost:
            raise JobLeaseLost("durable job lease was lost")
