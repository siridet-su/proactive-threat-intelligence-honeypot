"""Feed cache status helpers for dashboard visibility."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from production.utils.config import ProductionConfig
from production.utils.sensitive_data import redact_exception_for_log
from production.enrichment.cache_io import (
    CHECKSUM_FIELD,
    atomic_write_cache,
    checksum_valid,
)


RUNTIME_FEED_PROVENANCE_SCHEMA = "runtime_feed_provenance.v1"
GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
FEED_IMPORTERS: Dict[str, Dict[str, str]] = {
    "cisa": {
        "module": "production.enrichment.threat_feed_loader",
        "callable": "load_cisa_kev",
        "source": "cisa_kev_catalog",
        "expected_cache_schema": "1",
    },
    "sigma": {
        "module": "production.enrichment.threat_feed_loader",
        "callable": "load_sigma_rules",
        "source": "sigmahq_relevant_rules",
        "expected_cache_schema": "1",
    },
    "mitre": {
        "module": "production.enrichment.mitre_attack_loader",
        "callable": "load_mitre_attack_db",
        "source": "mitre_attack_enterprise_stix",
        "expected_cache_schema": "2",
    },
}


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


def _cache_status(
    path: str,
    count_field: str,
    max_age_days: int,
    expected_schema: str | None = None,
    importer: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    if not path:
        return {"status": "not_configured", "path": ""}
    cache_path = Path(path)
    if not cache_path.exists():
        return {"status": "missing", "path": str(cache_path)}
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("feed cache must contain a JSON object")
        if expected_schema is not None and raw.get("_schema") != expected_schema:
            raise ValueError("unsupported feed cache schema")
        if not checksum_valid(raw):
            raise ValueError("feed cache checksum mismatch")
        count = len(raw.get(count_field, {}))
        age = _age_days(raw.get("_fetched", ""))
        stale = age is None or age > max_age_days
        return {
            "status": "stale" if stale else "fresh",
            "path": str(cache_path),
            "age_days": age,
            "records": count,
            "last_success_at": raw.get("_fetched", ""),
            "checksum_verified": CHECKSUM_FIELD in raw,
            "cache_schema": raw.get("_schema", ""),
            "feed_version": raw.get("_version", ""),
            "cache_content_sha256": raw.get(CHECKSUM_FIELD, ""),
            "cache_file_sha256": hashlib.sha256(cache_path.read_bytes()).hexdigest(),
            "importer": dict(importer or {}),
        }
    except Exception as exc:
        return {
            "status": "corrupt",
            "path": str(cache_path),
            "error": redact_exception_for_log(exc),
        }


def collect_feed_status(config: ProductionConfig) -> Dict[str, Any]:
    cisa = _cache_status(
        config.cisa_cache_path, "entries", 1, "1", FEED_IMPORTERS["cisa"]
    )
    sigma = _cache_status(
        config.sigma_cache_path, "rules", 7, "1", FEED_IMPORTERS["sigma"]
    )
    mitre = _cache_status(
        config.mitre_attack_path, "techniques", 30, "2", FEED_IMPORTERS["mitre"]
    )
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


def _deployed_revision() -> str:
    configured = os.getenv("DEPLOYED_COMMIT", "").strip().lower()
    if GIT_REVISION_RE.fullmatch(configured):
        return configured
    root = Path(__file__).resolve().parents[2]
    for marker in (root / "DEPLOYED_COMMIT", root.parent / "DEPLOYED_COMMIT"):
        try:
            value = marker.read_text(encoding="utf-8").strip().lower()
        except OSError:
            continue
        if GIT_REVISION_RE.fullmatch(value):
            return value
    return ""


def _runtime_feed_provenance_path(config: ProductionConfig) -> Path | None:
    configured = str(getattr(config, "runtime_feed_provenance_path", "") or "").strip()
    if configured:
        return Path(configured)
    parents = {
        Path(path).parent
        for path in (
            config.cisa_cache_path,
            config.sigma_cache_path,
            config.mitre_attack_path,
        )
        if str(path).strip()
    }
    if len(parents) == 1:
        return next(iter(parents)) / "runtime_feed_provenance.json"
    return None


def runtime_feed_provenance(status: Dict[str, Any]) -> Dict[str, Any]:
    """Build a mutable, checksummed runtime record outside release identity."""
    revision = _deployed_revision()
    feeds: Dict[str, Dict[str, Any]] = {}
    for name in ("cisa", "sigma", "mitre"):
        item = status.get(name) or {}
        feeds[name] = {
            "status": item.get("status", ""),
            "cache_path": item.get("path", ""),
            "cache_file_sha256": item.get("cache_file_sha256", ""),
            "cache_content_sha256": item.get("cache_content_sha256", ""),
            "cache_schema": item.get("cache_schema", ""),
            "feed_version": item.get("feed_version", ""),
            "retrieved_at": item.get("last_success_at", ""),
            "records": item.get("records", 0),
            "importer": dict(item.get("importer") or FEED_IMPORTERS[name]),
            "evaluator_git_revision": revision,
            "authority": "non_authoritative_context_only",
        }
    return {
        "_schema": RUNTIME_FEED_PROVENANCE_SCHEMA,
        "schema_version": RUNTIME_FEED_PROVENANCE_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "writer": {
            "module": "production.enrichment.feed_status",
            "callable": "write_runtime_feed_provenance",
            "evaluator_git_revision": revision,
        },
        "authority": "non_authoritative_context_only",
        "feeds": feeds,
    }


def write_runtime_feed_provenance(
    config: ProductionConfig,
    status: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Atomically persist feed provenance without binding it to a release hash."""
    path = _runtime_feed_provenance_path(config)
    if path is None:
        return {"recorded": False, "reason": "feed_paths_not_configured"}
    document = runtime_feed_provenance(status or collect_feed_status(config))
    atomic_write_cache(str(path), document)
    return {
        "recorded": True,
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "schema_version": RUNTIME_FEED_PROVENANCE_SCHEMA,
    }


def save_feed_status(storage: Any, config: ProductionConfig) -> Dict[str, Any]:
    status = collect_feed_status(config)
    storage.save_feed_status(status)
    return status
