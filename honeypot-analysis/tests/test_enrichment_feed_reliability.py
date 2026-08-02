from __future__ import annotations

import json
import time
import urllib.error
from types import SimpleNamespace

import pytest

import production.enrichment.cache_io as cache_io
import production.enrichment.mitre_attack_loader as mitre_loader
import production.enrichment.threat_feed_loader as feed_loader
from production.enrichment.cache_io import (
    atomic_write_cache,
    feed_refresh_lock,
    load_cache_json,
)
from production.enrichment.enrichment_providers import (
    HTTPProvider,
    OTXProvider,
    ProviderResult,
    merge_provider_results,
)
from production.enrichment.feed_status import _cache_status
from production.enrichment.mitre_attack_loader import MitreAttackDB, TechniqueRecord
from production.enrichment.refresh_feeds import refresh_feeds
from production.utils.config import ProductionConfig
from production.workers.enrichment_worker import EnrichmentWorker


class _DelayedProvider:
    supported_types = {"ip"}

    def __init__(self, name: str, delay: float, result: ProviderResult) -> None:
        self.name = name
        self.delay = delay
        self.result = result

    def supports(self, observable_type: str) -> bool:
        return observable_type in self.supported_types

    def enrich(self, *_args: object) -> ProviderResult:
        time.sleep(self.delay)
        return self.result


class _Response:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.body = body
        self.headers = headers or {}

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int = -1) -> bytes:
        return self.body if limit < 0 else self.body[:limit]


def test_provider_execution_is_bounded_parallel_and_ordered() -> None:
    providers = [
        _DelayedProvider(
            name,
            0.08,
            ProviderResult(name, "ok", {"value": name}),
        )
        for name in ("first", "second", "third")
    ]
    worker = object.__new__(EnrichmentWorker)
    worker.config = SimpleNamespace(
        enrichment_ttl_seconds=3600,
        enrichment_provider_workers=3,
    )
    worker.providers = providers

    started = time.monotonic()
    results = worker._run_providers("ip", "203.0.113.10")
    elapsed = time.monotonic() - started

    assert elapsed < 0.20
    assert [result.provider for result in results] == ["first", "second", "third"]


def test_http_provider_retries_rate_limit_and_bounds_response(monkeypatch) -> None:
    attempts = 0

    def rate_limited(*_args: object, **_kwargs: object) -> _Response:
        nonlocal attempts
        attempts += 1
        raise urllib.error.HTTPError("https://provider", 429, "limited", None, None)

    monkeypatch.setattr("urllib.request.urlopen", rate_limited)
    provider = OTXProvider(
        "configured",
        retries=1,
        retry_delay_seconds=0,
        max_response_bytes=1024,
    )
    result = provider.enrich("ip", "203.0.113.11")
    assert attempts == 2
    assert result.status == "rate_limited"

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: _Response(b"{" + b"x" * 2048 + b"}"),
    )
    helper = HTTPProvider(max_response_bytes=1024, retries=0)
    with pytest.raises(ValueError, match="exceeds configured limit"):
        helper._json_get("https://provider")


def test_merge_is_non_null_bounded_redacted_and_has_per_provider_ttls() -> None:
    results = [
        ProviderResult(
            "shodan",
            "ok",
            {"country_code": None, "org": None, "tags": ["x" * 400] * 300},
            ttl_seconds=120,
            fetched_at="2026-01-01T00:00:00+00:00",
        ),
        ProviderResult(
            "censys",
            "ok",
            {
                "result": {
                    "location": {"country_code": "US"},
                    "autonomous_system": {"name": "Example ISP"},
                }
            },
            ttl_seconds=240,
            fetched_at="2026-01-01T00:00:00+00:00",
        ),
        ProviderResult(
            "static",
            "ok",
            {"api_token": "must-not-survive", "large": "y" * 10_000},
            ttl_seconds=300,
        ),
    ]

    payload, status, _ = merge_provider_results("ip", "203.0.113.12", results)

    assert payload["country"] == "US"
    assert payload["isp"] == "Example ISP"
    assert payload["api_token"] == "[REDACTED]"
    assert len(payload["large"]) == 4096
    assert len(payload["shodan_tags"]) == 1
    assert len(payload["shodan_tags"][0]) == 256
    assert status["shodan"]["expires_at"] == "2026-01-01T00:02:00+00:00"
    assert payload["enrichment_cache"]["overall_status"] == "complete_success"


def test_partial_and_failure_statuses_have_explicit_retry_semantics() -> None:
    partial, _, _ = merge_provider_results(
        "ip",
        "203.0.113.13",
        [
            ProviderResult("one", "ok", {}),
            ProviderResult("two", "temporary_error", error="TimeoutError: operation_failed"),
        ],
    )
    failed, _, _ = merge_provider_results(
        "ip",
        "203.0.113.14",
        [ProviderResult("one", "permanent_error", error="ValueError: operation_failed")],
    )
    unavailable, _, _ = merge_provider_results(
        "ip",
        "203.0.113.15",
        [ProviderResult("one", "not_configured")],
    )

    assert partial["enrichment_cache"]["overall_status"] == "partial_success"
    assert failed["enrichment_cache"]["overall_status"] == "permanent_failure"
    assert unavailable["enrichment_cache"]["overall_status"] == "unavailable"


def test_atomic_cache_failure_preserves_last_good_file(tmp_path, monkeypatch) -> None:
    path = tmp_path / "feed.json"
    atomic_write_cache(str(path), {"_schema": "1", "entries": {"old": {}}})
    original = path.read_bytes()
    monkeypatch.setattr(cache_io.os, "replace", lambda *_args: (_ for _ in ()).throw(OSError("failure")))

    with pytest.raises(OSError):
        atomic_write_cache(str(path), {"_schema": "1", "entries": {"new": {}}})

    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".*.tmp"))


def test_cache_schema_checksum_and_lock_are_enforced(tmp_path) -> None:
    path = tmp_path / "feed.json"
    atomic_write_cache(str(path), {"_schema": "1", "entries": {"safe": {}}})
    assert load_cache_json(str(path), "1")["entries"] == {"safe": {}}

    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["entries"]["tampered"] = {}
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="checksum mismatch"):
        load_cache_json(str(path), "1")
    assert _cache_status(str(path), "entries", 1, "1")["status"] == "corrupt"

    with feed_refresh_lock(str(path)):
        with pytest.raises(TimeoutError):
            with feed_refresh_lock(str(path), timeout_seconds=0):
                pass


def test_failed_feed_refresh_uses_last_verified_stale_cache(tmp_path, monkeypatch) -> None:
    path = tmp_path / "cisa.json"
    atomic_write_cache(
        str(path),
        {
            "_schema": "1",
            "_fetched": "2000-01-01T00:00:00+00:00",
            "catalog_version": "legacy",
            "entries": {
                "CVE-2026-0001": {
                    "vendor": "Example",
                    "product": "Widget",
                    "name": "Example issue",
                    "date_added": "2026-01-01",
                }
            },
        },
    )
    before = path.read_bytes()
    monkeypatch.setattr(feed_loader, "_fetch_cisa_kev", lambda: None)

    db = feed_loader.load_cisa_kev(force_refresh=True, cache_path=str(path))

    assert db.count == 1
    assert db.is_actively_exploited("CVE-2026-0001") is True
    assert path.read_bytes() == before


def test_runtime_cache_load_never_refreshes_network(tmp_path, monkeypatch) -> None:
    path = tmp_path / "cisa.json"
    atomic_write_cache(
        str(path),
        {
            "_schema": "1",
            "_fetched": "2000-01-01T00:00:00+00:00",
            "catalog_version": "stale",
            "entries": {},
        },
    )
    monkeypatch.setattr(
        feed_loader,
        "_fetch_cisa_kev",
        lambda: (_ for _ in ()).throw(AssertionError("network refresh attempted")),
    )

    db = feed_loader.load_cisa_kev(
        cache_path=str(path),
        allow_network_refresh=False,
    )

    assert db.catalog_version == "stale"


def test_explicit_feed_paths_do_not_poison_default_singletons(tmp_path, monkeypatch) -> None:
    explicit = tmp_path / "mitre.json"
    db = MitreAttackDB(
        {"T0001": TechniqueRecord("T0001", "Explicit")},
        version="explicit",
    )
    atomic_write_cache(str(explicit), db.to_cache_dict())
    mitre_loader.clear_singleton()
    loaded = mitre_loader.load_mitre_attack_db(str(explicit), silent=True)
    assert loaded.version == "explicit"

    default = tmp_path / "default.json"
    default_db = MitreAttackDB(
        {"T0002": TechniqueRecord("T0002", "Default")},
        version="default",
    )
    atomic_write_cache(str(default), default_db.to_cache_dict())
    monkeypatch.setattr(mitre_loader, "_cache_path", lambda: str(default))
    assert mitre_loader.load_mitre_attack_db(silent=True).version == "default"

    feed_loader._GLOBAL_FEEDS = None
    monkeypatch.setattr(feed_loader, "load_cisa_kev", lambda **_kwargs: feed_loader.CisaKevDB({}, "x"))
    monkeypatch.setattr(feed_loader, "load_sigma_rules", lambda **_kwargs: feed_loader.SigmaRuleDB([]))
    explicit_feeds = feed_loader.load_threat_feeds(cisa_cache_path="explicit")
    assert feed_loader._GLOBAL_FEEDS is None
    assert explicit_feeds.kev.catalog_version == "x"


def test_feed_loading_disabled_is_a_complete_offline_path(tmp_path, monkeypatch) -> None:
    config = ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'disabled.db'}",
        enable_feed_loading=False,
    )
    monkeypatch.setattr(
        "production.enrichment.refresh_feeds.load_cisa_kev",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("network path called")),
    )

    result = refresh_feeds(config)

    assert result["status"] == "disabled"
    assert result["loading_enabled"] is False


def test_refresh_records_checksums_and_importer_provenance_outside_release(
    tmp_path,
    monkeypatch,
) -> None:
    cisa = tmp_path / "cisa_kev_cache.json"
    sigma = tmp_path / "sigma_rules_cache.json"
    mitre = tmp_path / "mitre_attack_cache.json"
    provenance = tmp_path / "runtime_feed_provenance.json"
    fetched = "2026-07-29T00:00:00+00:00"
    atomic_write_cache(
        str(cisa),
        {"_schema": "1", "_fetched": fetched, "_version": "kev", "entries": {}},
    )
    atomic_write_cache(
        str(sigma),
        {"_schema": "1", "_fetched": fetched, "_version": "sigma", "rules": {}},
    )
    atomic_write_cache(
        str(mitre),
        {"_schema": "2", "_fetched": fetched, "_version": "14.1", "techniques": {}},
    )
    config = ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'feeds.db'}",
        enable_feed_loading=False,
        cisa_cache_path=str(cisa),
        sigma_cache_path=str(sigma),
        mitre_attack_path=str(mitre),
        runtime_feed_provenance_path=str(provenance),
    )
    monkeypatch.setenv("DEPLOYED_COMMIT", "a" * 40)

    result = refresh_feeds(config)
    document = load_cache_json(str(provenance), "runtime_feed_provenance.v1")

    assert result["status"] == "disabled"
    assert result["runtime_feed_provenance"]["recorded"] is True
    assert document["authority"] == "non_authoritative_context_only"
    assert document["feeds"]["mitre"]["feed_version"] == "14.1"
    assert document["feeds"]["mitre"]["cache_file_sha256"]
    assert document["feeds"]["mitre"]["cache_content_sha256"]
    assert document["feeds"]["mitre"]["retrieved_at"] == fetched
    assert document["feeds"]["mitre"]["importer"]["callable"] == (
        "load_mitre_attack_db"
    )
    assert document["feeds"]["mitre"]["evaluator_git_revision"] == "a" * 40
