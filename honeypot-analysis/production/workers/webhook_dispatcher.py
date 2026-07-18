"""Webhook alert dispatcher with retryable delivery records."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from production.utils.config import ProductionConfig
from production.utils.sensitive_data import redact_exception_for_log
from production.utils.serialization import stable_id, utc_now
from production.storage import open_storage


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def target_hash(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def post_webhook(url: str, payload: Dict[str, Any], timeout_seconds: float) -> Tuple[bool, str]:
    try:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            if 200 <= response.status < 300:
                return True, ""
            return False, f"HTTP {response.status}"
    except Exception as exc:
        return False, redact_exception_for_log(exc)


class WebhookDispatcher:
    def __init__(self, config: ProductionConfig) -> None:
        self.config = config
        self.storage = open_storage(config.database_url)

    def _alert_should_send(self, alert: Dict[str, Any]) -> bool:
        policy = self.config.webhook_policy or {}
        alert_type = str(alert.get("alert_type") or (alert.get("payload") or {}).get("alert_type") or "").strip().lower()
        default_min = str(policy.get("min_severity") or "high").strip().lower()
        per_type = policy.get("alert_type_min_severity") or {}
        min_severity = str(per_type.get(alert_type) or default_min).strip().lower()
        severity = str(alert.get("severity") or "").strip().lower()
        return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(min_severity, 3)

    def dispatch_once(self) -> int:
        if not self.config.webhook_url:
            return 0
        attempted = 0
        target = target_hash(self.config.webhook_url)
        for row in self.storage.pending_webhooks(limit=100):
            alert = row["payload"]
            if not self._alert_should_send(alert):
                continue
            payload = {"type": "alert", "alert": alert, "timestamp": utc_now()}
            delivery_id = stable_id("delivery", {"alert_id": row["alert_id"], "report_id": None, "target": target})
            existing = self.storage.get_webhook_delivery(delivery_id)
            if existing and int(existing.get("attempts", 0)) >= self.config.webhook_max_attempts:
                continue
            ok, error = post_webhook(self.config.webhook_url, payload, self.config.webhook_timeout_seconds)
            self.storage.record_webhook_delivery(
                payload,
                target,
                "delivered" if ok else "failed",
                error=error,
                alert_id=row["alert_id"],
            )
            attempted += 1
        return attempted

    def run_forever(self) -> None:
        while True:
            attempted = self.dispatch_once()
            print(
                json.dumps(
                    {
                        "service": "webhook_dispatcher",
                        "attempted": attempted,
                        "timestamp": utc_now(),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            time.sleep(self.config.webhook_retry_seconds)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run webhook alert dispatch.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--once", action="store_true", help="Dispatch once and exit.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    dispatcher = WebhookDispatcher(config)
    if args.once:
        attempted = dispatcher.dispatch_once()
        print(json.dumps({"service": "webhook_dispatcher", "attempted": attempted}, sort_keys=True))
        return 0
    dispatcher.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
