"""Feed cache status helpers for dashboard visibility."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from production.utils.config import ProductionConfig
from production.utils.sensitive_data import redact_exception_for_log


def _age_days(raw_fetched: str) -> float | None:
    if not raw_fetched:
        return None
    try:
        fetched = datetime.fromisoformat(raw_fetched.replace("Z", "+00:00"))
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=timezone.utc)
        return round((datetime.now(timezone.utc) - fetched).total_seconds() / 86400, 2)
    except ValueError:
        return None


def _cache_status(path: str, count_field: str, max_age_days: int) -> Dict[str, Any]:
    if not path:
        return {"status": "not_configured", "path": ""}
    cache_path = Path(path)
    if not cache_path.exists():
        return {"status": "missing", "path": str(cache_path)}
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
        count = len(raw.get(count_field, {}))
        age = _age_days(raw.get("_fetched", ""))
        stale = age is None or age > max_age_days
        return {
            "status": "stale" if stale else "fresh",
            "path": str(cache_path),
            "age_days": age,
            "records": count,
        }
    except Exception as exc:
        return {
            "status": "corrupt",
            "path": str(cache_path),
            "error": redact_exception_for_log(exc),
        }


def collect_feed_status(config: ProductionConfig) -> Dict[str, Any]:
    cisa = _cache_status(config.cisa_cache_path, "entries", 1)
    sigma = _cache_status(config.sigma_cache_path, "rules", 7)
    mitre = _cache_status(config.mitre_attack_path, "techniques", 30)
    stale = [
        name for name, item in {"cisa": cisa, "sigma": sigma, "mitre": mitre}.items()
        if item["status"] in {"missing", "stale", "corrupt", "not_configured"}
    ]
    return {
        "cisa": cisa,
        "sigma": sigma,
        "mitre": mitre,
        "summary": "All feeds fresh" if not stale else f"Needs attention: {', '.join(stale)}",
    }


def save_feed_status(storage: Any, config: ProductionConfig) -> Dict[str, Any]:
    status = collect_feed_status(config)
    storage.save_feed_status(status)
    return status
