"""Local-only validation for the non-authoritative source-IP cache sink."""

from __future__ import annotations

import concurrent.futures
import json
from pathlib import Path

import pytest

from production.enrichment.enrichment_cache import (
    MAX_CACHE_HOSTNAMES,
    MAX_CACHE_PORTS,
    MAX_CACHE_SERVICES,
    MAX_CACHE_TAGS,
    MAX_NORMALIZED_CACHE_CONTEXT_BYTES,
    MAX_NORMALIZED_CACHE_ENTRY_BYTES,
    SOURCE_IP_CACHE_COLLECTION,
    SOURCE_IP_CACHE_SCHEMA,
    SOURCE_IP_CACHE_PROVIDERS,
    SourceIPCacheService,
    SourceIPCacheUnavailable,
    build_source_ip_cache_entry,
)
from production.enrichment.enrichment_providers import (
    EnrichmentProvider,
    ProviderResult,
)
from production.enrichment.external_ti_contract import (
    SOURCE_IP_AMENDMENT_SHA256,
    SOURCE_IP_ENRICHMENT_MODE,
    default_external_ti_provider_configs,
    provider_config_identity,
)
from production.storage.backend import SQLiteStorage
from production.utils.config import ProductionConfig
from production.workers.enrichment_worker import EnrichmentWorker


SOURCE_IP_POLICY_PATH = (
    Path(__file__).resolve().parents[1]
    / "configs"
    / "external_ti_source_ip_governance_amendment.v1.json"
)
CUTOFF = "2026-09-05T08:00:00Z"
FIXTURE_IP = "9.9.9.9"


def _storage(tmp_path: Path) -> SQLiteStorage:
    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'source-ip-cache.db'}")
    storage.initialize()
    return storage


def _settings(provider: str) -> dict[str, object]:
    settings = dict(default_external_ti_provider_configs()[provider])
    settings.update({"enabled": True, "minute_limit": 10, "daily_budget": 10})
    return settings


def _source_config(tmp_path: Path, providers: tuple[str, ...] = ("abuseipdb",)) -> ProductionConfig:
    configs = default_external_ti_provider_configs()
    for provider in providers:
        configs[provider].update(
            {"enabled": True, "minute_limit": 10, "daily_budget": 10}
        )
    return ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'worker.db'}",
        external_enrichment_profile="source_ip_observables",
        external_ti_enabled=True,
        external_ti_provider_allowlist=list(providers),
        external_ti_provider_configs=configs,
        source_ip_enrichment_mode=SOURCE_IP_ENRICHMENT_MODE,
        source_ip_enrichment_not_before_utc=CUTOFF,
        source_ip_enrichment_cutoff_operator="durable-cache-test",
        source_ip_governance_path=str(SOURCE_IP_POLICY_PATH),
        source_ip_governance_sha256=SOURCE_IP_AMENDMENT_SHA256,
        external_ti_proof_campaign_id="durable-cache-test-campaign",
        external_ti_proof_guard_mode="REAL_PROOF",
    )


def _result(provider: str, data: dict, status: str = "ok") -> ProviderResult:
    return ProviderResult(
        provider,
        status,
        data=data,
        ttl_seconds=86_400,
        endpoint_id=_settings(provider)["endpoint_id"],
        provider_mode=_settings(provider)["mode"],
        attempt_count=1,
    )


def test_abuseipdb_data_persists_bounded_context(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    service = SourceIPCacheService(storage)
    entry = service.store_result(
        "abuseipdb",
        FIXTURE_IP,
        _result(
            "abuseipdb",
            {
                "data": {
                    "abuseConfidenceScore": 42,
                    "totalReports": 3,
                    "categories": [18, 22],
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "fixture-isp",
                    "countryCode": "US",
                    "lastReportedAt": "2026-09-04T00:00:00Z",
                }
            },
        ),
        _settings("abuseipdb"),
        now="2026-09-05T09:00:00Z",
    )
    assert entry is not None
    assert entry["lookup_status"] == "DATA"
    assert entry["provenance"]["cache_authority"] == "NON_AUTHORITATIVE_CACHE"
    assert entry["provenance"]["privacy_policy_identity"].startswith(
        "honeypot-thesis-data-lifecycle.source-ip"
    )
    assert service.lookup("abuseipdb", FIXTURE_IP, now="2026-09-05T10:00:00Z")
    assert len(storage.list_rows(SOURCE_IP_CACHE_COLLECTION)) == 1
    encoded = json.dumps(storage.list_rows(SOURCE_IP_CACHE_COLLECTION), sort_keys=True)
    assert '"reports"' not in encoded
    assert "api_key" not in encoded.lower()
    assert "password" not in encoded.lower()


def test_otx_source_ip_data_persists_bounded_pulse_context(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    service = SourceIPCacheService(storage)
    entry = service.store_result(
        "otx",
        FIXTURE_IP,
        _result(
            "otx",
            {
                "pulse_info": {
                    "pulses": [
                        {
                            "id": "pulse-1",
                            "name": "bounded fixture pulse",
                            "created": "2026-09-04T00:00:00Z",
                            "modified": "2026-09-04T01:00:00Z",
                            "tags": ["malware", "fixture"],
                            "references": ["https://example.invalid/pulse-1"],
                        }
                    ]
                }
            },
        ),
        _settings("otx"),
        now="2026-09-05T09:00:00Z",
    )
    assert entry is not None
    assert entry["lookup_status"] == "DATA"
    assert entry["normalized_context"]["pulses"][0]["pulse_id"] == "pulse-1"
    encoded = json.dumps(entry, sort_keys=True)
    assert "pulse_info" not in encoded
    assert "api_key" not in encoded.lower()
    assert "password" not in encoded.lower()


def test_shodan_data_persists_only_bounded_normalized_context(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    service = SourceIPCacheService(storage)
    entry = service.store_result(
        "shodan_official",
        FIXTURE_IP,
        _result(
            "shodan_official",
            {
                "org": "fixture organization",
                "isp": "fixture isp",
                "country_name": "US",
                "ports": [22, "443", "bad-port", 22],
                "data": [
                    {"product": "OpenSSH", "port": 22, "banner": "secret-banner"},
                    {"product": "nginx", "port": 443},
                ],
                "hostnames": ["fixture.example"],
                "tags": ["cloud"],
                "last_update": "2026-09-04T00:00:00Z",
            },
        ),
        _settings("shodan_official"),
        now="2026-09-05T09:00:00Z",
    )
    assert entry is not None
    context = entry["normalized_context"]
    assert context["ports"] == [22, 443]
    assert "secret-banner" not in json.dumps(entry)
    assert "data" not in context
    assert len(json.dumps(context, sort_keys=True).encode()) <= MAX_NORMALIZED_CACHE_CONTEXT_BYTES
    assert len(json.dumps(entry, sort_keys=True).encode()) <= MAX_NORMALIZED_CACHE_ENTRY_BYTES


def test_shodan_no_data_is_a_durable_negative_cache(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    service = SourceIPCacheService(storage)
    service.store_result(
        "shodan_official",
        FIXTURE_IP,
        _result("shodan_official", {}, status="not_found"),
        _settings("shodan_official"),
        now="2026-09-05T09:00:00Z",
    )
    hit = service.lookup("shodan_official", FIXTURE_IP, now="2026-09-05T10:00:00Z")
    assert hit is not None
    assert hit["lookup_status"] == "NO_DATA"
    assert hit["negative_cache_until"] == hit["expires_at"]
    cached = SourceIPCacheService.cached_result(hit).to_status()
    assert cached["provider_evidence"]["lookup_status"] == "NOT_FOUND"


def test_fresh_same_provider_ip_requires_no_new_lookup_and_providers_stay_distinct(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path)
    service = SourceIPCacheService(storage)
    for provider in sorted(SOURCE_IP_CACHE_PROVIDERS):
        service.store_result(
            provider,
            FIXTURE_IP,
            _result(provider, {"ports": [443]} if provider.startswith("shodan") else {"data": {"totalReports": 1}}),
            _settings(provider),
            now="2026-09-05T09:00:00Z",
        )
    calls = 0
    for provider in sorted(SOURCE_IP_CACHE_PROVIDERS):
        settings = _settings(provider)
        if service.lookup(
            provider,
            FIXTURE_IP,
            expected_config_identity=provider_config_identity(provider, settings),
            now="2026-09-05T10:00:00Z",
        ) is None:
            calls += 1
    assert calls == 0
    rows = storage.list_rows(SOURCE_IP_CACHE_COLLECTION)
    assert len(rows) == len(SOURCE_IP_CACHE_PROVIDERS)
    assert {row["provider"] for row in rows} == set(SOURCE_IP_CACHE_PROVIDERS)


def test_cache_survives_simulated_worker_restart(tmp_path: Path) -> None:
    first_storage = _storage(tmp_path)
    first = SourceIPCacheService(first_storage)
    first.store_result(
        "abuseipdb",
        FIXTURE_IP,
        _result("abuseipdb", {"data": {"abuseConfidenceScore": 10}}),
        _settings("abuseipdb"),
        now="2026-09-05T09:00:00Z",
    )
    restarted_storage = SQLiteStorage(f"sqlite:///{tmp_path / 'source-ip-cache.db'}")
    restarted = SourceIPCacheService(restarted_storage)
    hit = restarted.lookup("abuseipdb", FIXTURE_IP, now="2026-09-05T10:00:00Z")
    assert hit is not None
    assert hit["normalized_context"]["abuse_confidence_score"] == 10


@pytest.mark.parametrize("status", ["ok", "not_found"])
def test_expired_positive_and_negative_entries_become_refresh_eligible(
    tmp_path: Path, status: str
) -> None:
    storage = _storage(tmp_path)
    service = SourceIPCacheService(storage)
    data = {"ports": [443]} if status == "ok" else {}
    result = _result("shodan_official", data, status=status)
    service.store_result(
        "shodan_official",
        FIXTURE_IP,
        result,
        _settings("shodan_official"),
        now="2026-09-05T09:00:00Z",
    )
    assert service.lookup(
        "shodan_official", FIXTURE_IP, now="2026-09-06T09:01:00Z"
    ) is None


@pytest.mark.parametrize(
    ("result_status", "cache_status"),
    [
        ("auth_disabled", "AUTH_FAILED"),
        ("rate_limited", "RATE_LIMITED"),
        ("temporary_error", "REQUEST_FAILED"),
        ("malformed_response", "NORMALIZATION_FAILED"),
    ],
)
def test_provider_failure_states_are_bounded_and_distinct(
    tmp_path: Path, result_status: str, cache_status: str
) -> None:
    storage = _storage(tmp_path)
    service = SourceIPCacheService(storage)
    result = _result("shodan_official", {}, status=result_status)
    entry = service.store_result(
        "shodan_official",
        FIXTURE_IP,
        result,
        _settings("shodan_official"),
        now="2026-09-05T09:00:00Z",
    )
    assert entry is not None
    assert entry["lookup_status"] == cache_status
    assert entry["normalized_context"] == {}
    assert service.lookup(
        "shodan_official", FIXTURE_IP, now="2026-09-05T09:01:00Z"
    )["lookup_status"] == cache_status
    assert "error" not in entry


def test_expired_rows_are_removed_only_by_bounded_maintenance(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    service = SourceIPCacheService(storage)
    service.store_result(
        "abuseipdb",
        FIXTURE_IP,
        _result("abuseipdb", {"data": {"abuseConfidenceScore": 1}}),
        _settings("abuseipdb"),
        now="2026-09-05T09:00:00Z",
    )
    assert len(storage.list_rows(SOURCE_IP_CACHE_COLLECTION)) == 1
    assert service.prune_expired(now="2026-09-06T09:00:00Z", max_records=1) == 1
    assert storage.list_rows(SOURCE_IP_CACHE_COLLECTION) == []


def test_malformed_optional_shodan_fields_are_bounded_and_raw_payload_is_absent(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path)
    service = SourceIPCacheService(storage)
    entry = service.store_result(
        "shodan_official",
        FIXTURE_IP,
        _result(
            "shodan_official",
            {
                "hostnames": ["h" * 10_000] * 100,
                "tags": ["t" * 10_000] * 100,
                "services": [{"product": "p" * 10_000, "banner": "raw-secret-banner"}] * 100,
                "ports": [1, 2, 3, "not-a-port"] * 100,
                "api_key": "fixture-secret-key",
            },
        ),
        _settings("shodan_official"),
        now="2026-09-05T09:00:00Z",
    )
    assert entry is not None
    context = entry["normalized_context"]
    assert len(context.get("hostnames", [])) <= MAX_CACHE_HOSTNAMES
    assert len(context.get("tags", [])) <= MAX_CACHE_TAGS
    assert len(context.get("service_product_summary", [])) <= MAX_CACHE_SERVICES
    assert len(context.get("ports", [])) <= MAX_CACHE_PORTS
    encoded = json.dumps(entry, sort_keys=True).lower()
    assert "raw-secret-banner" not in encoded
    assert "fixture-secret-key" not in encoded
    assert "api_key" not in encoded


def test_concurrent_logical_writes_are_idempotent_and_bounded(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    service = SourceIPCacheService(storage)
    settings = _settings("shodan_official")

    def write_once() -> None:
        service.store_result(
            "shodan_official",
            FIXTURE_IP,
            _result("shodan_official", {"ports": [443]}),
            settings,
            now="2026-09-05T09:00:00Z",
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda _item: write_once(), range(16)))
    rows = storage.list_rows(SOURCE_IP_CACHE_COLLECTION)
    assert len(rows) == 1
    assert rows[0]["provider"] == "shodan_official"


def test_cache_backend_failure_suppresses_provider_lookup(tmp_path: Path) -> None:
    config = _source_config(tmp_path)

    class _Provider(EnrichmentProvider):
        external = True
        requires_credential = False
        name = "abuseipdb"
        supported_types = {"ip"}

        def __init__(self) -> None:
            self.calls = 0

        def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
            self.calls += 1
            return _result(self.name, {"data": {"totalReports": 1}})

    class _UnavailableStorage:
        def get_external_ti_source_ip_cache(self, *args, **kwargs):
            raise RuntimeError("fixture backend unavailable")

    provider = _Provider()
    worker = EnrichmentWorker(config, providers=[provider])
    worker.source_ip_cache = SourceIPCacheService(_UnavailableStorage())
    results = worker._run_providers(
        "ip",
        FIXTURE_IP,
        sighting={
            "observable_type": "ip",
            "observable_value": FIXTURE_IP,
            "role": "source_ip",
            "source": "cowrie_event",
            "session_id": "cache-test-session",
            "timestamp": "2026-09-05T09:00:00Z",
        },
    )
    assert provider.calls == 0
    assert results[0].status == "disabled"
    assert results[0].data == {"gate": "source_ip_cache_unavailable"}


def test_cache_write_failure_does_not_block_optional_core_job(tmp_path: Path) -> None:
    config = _source_config(tmp_path)

    class _Provider(EnrichmentProvider):
        external = True
        requires_credential = False
        name = "abuseipdb"
        supported_types = {"ip"}

        def __init__(self) -> None:
            self.calls = 0

        def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
            self.calls += 1
            return _result(self.name, {"data": {"totalReports": 1}})

    class _WriteUnavailableStorage:
        def get_external_ti_source_ip_cache(self, *args, **kwargs):
            return None

        def upsert_external_ti_source_ip_cache(self, *args, **kwargs):
            raise RuntimeError("fixture cache write unavailable")

    provider = _Provider()
    worker = EnrichmentWorker(config, providers=[provider])
    worker.source_ip_cache = SourceIPCacheService(_WriteUnavailableStorage())
    worker.storage.enqueue_enrichment_job(
        "ip",
        FIXTURE_IP,
        session_id="cache-write-failure-session",
        payload={
            "role": "source_ip",
            "source": "cowrie_event",
            "event_id": "cache-write-failure-event",
            "eventid": "cowrie.session.connect",
            "sensor_id": "cache-sensor",
            "timestamp": "2026-09-05T09:00:00Z",
        },
    )
    assert worker.process_once() == 1
    assert provider.calls == 1
    assert worker.storage.list_rows("enrichment_jobs")[0]["status"] == "succeeded"


def test_worker_persists_source_cache_and_next_worker_uses_it_without_provider_call(
    tmp_path: Path,
) -> None:
    config = _source_config(tmp_path)

    class _Provider(EnrichmentProvider):
        external = True
        requires_credential = False
        name = "abuseipdb"
        supported_types = {"ip"}

        def __init__(self) -> None:
            self.calls = 0

        def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
            self.calls += 1
            return _result(self.name, {"data": {"abuseConfidenceScore": 11}})

    first_provider = _Provider()
    first_worker = EnrichmentWorker(config, providers=[first_provider])
    first_worker.storage.enqueue_enrichment_job(
        "ip",
        FIXTURE_IP,
        session_id="cache-test-session",
        payload={
            "role": "source_ip",
            "source": "cowrie_event",
            "event_id": "cache-event-1",
            "eventid": "cowrie.session.connect",
            "sensor_id": "cache-sensor",
            "timestamp": "2026-09-05T09:00:00Z",
        },
    )
    assert first_worker.process_once() == 1
    assert first_provider.calls == 1

    second_provider = _Provider()
    second_worker = EnrichmentWorker(config, providers=[second_provider])
    job_id, queued = second_worker.storage.enqueue_enrichment_job(
        "ip",
        FIXTURE_IP,
        session_id="cache-test-session-2",
        payload={
            "role": "source_ip",
            "source": "cowrie_event",
            "event_id": "cache-event-2",
            "eventid": "cowrie.session.connect",
            "sensor_id": "cache-sensor",
            "timestamp": "2026-09-05T09:01:00Z",
        },
    )
    assert job_id == first_worker.storage.list_rows("enrichment_jobs")[0]["job_id"]
    assert queued is False
    assert second_worker.process_once() == 0
    assert second_provider.calls == 0
    assert second_worker.storage.get_enrichment_record("ip", FIXTURE_IP, True) is None
    job = second_worker.storage.list_rows("enrichment_jobs")[0]
    assert job["status"] == "succeeded"
    assert job["attempts"] == 1


def test_failed_terminal_job_is_preserved_without_explicit_force(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    job_id, inserted = storage.enqueue_enrichment_job(
        "ip",
        FIXTURE_IP,
        session_id="failed-predecessor-session",
        payload={"role": "source_ip", "timestamp": CUTOFF},
    )
    assert inserted
    claim = storage.claim_enrichment_jobs("worker", 1, 600, 1)[0]
    assert storage.fail_enrichment_job(
        job_id,
        claim["claim_owner"],
        claim["claim_token"],
        "enrichment_failed",
        "RuntimeError",
        False,
        1,
        0,
    ) == "failed"
    before = next(row for row in storage.list_rows("enrichment_jobs") if row["job_id"] == job_id)

    duplicate_id, duplicate_queued = storage.enqueue_enrichment_job(
        "ip",
        FIXTURE_IP,
        session_id="new-observation-session",
        payload={"role": "source_ip", "timestamp": "2026-09-05T09:01:00Z"},
    )
    assert duplicate_id == job_id
    assert duplicate_queued is False
    after = next(row for row in storage.list_rows("enrichment_jobs") if row["job_id"] == job_id)
    assert after["status"] == "failed"
    assert after["attempts"] == before["attempts"] == 1
    assert after["last_error_code"] == before["last_error_code"] == "enrichment_failed"
    assert after["last_error_type"] == before["last_error_type"] == "RuntimeError"

    forced_id, forced_queued = storage.enqueue_enrichment_job(
        "ip",
        FIXTURE_IP,
        session_id="explicit-retry-session",
        payload={"role": "source_ip", "timestamp": "2026-09-05T09:02:00Z"},
        force=True,
    )
    assert forced_id == job_id
    assert forced_queued is True
    reset = next(row for row in storage.list_rows("enrichment_jobs") if row["job_id"] == job_id)
    assert reset["status"] == "queued"
    assert reset["attempts"] == 0
    assert reset["last_error_code"] is None
    assert reset["last_error_type"] is None


def test_cache_miss_does_not_bypass_historical_source_ip_cutoff(tmp_path: Path) -> None:
    config = _source_config(tmp_path)

    class _Provider(EnrichmentProvider):
        external = True
        requires_credential = False
        name = "abuseipdb"
        supported_types = {"ip"}

        def __init__(self) -> None:
            self.calls = 0

        def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
            self.calls += 1
            return _result(self.name, {"data": {"totalReports": 1}})

    provider = _Provider()
    worker = EnrichmentWorker(config, providers=[provider])
    results = worker._run_providers(
        "ip",
        FIXTURE_IP,
        sighting={
            "observable_type": "ip",
            "observable_value": FIXTURE_IP,
            "role": "source_ip",
            "source": "cowrie_event",
            "session_id": "cache-test-session",
            "timestamp": "2026-09-05T07:59:59Z",
        },
    )
    assert provider.calls == 0
    assert results[0].status == "policy_prohibited"


def test_cache_is_not_canonical_or_full_session_payload(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    service = SourceIPCacheService(storage)
    entry = service.store_result(
        "abuseipdb",
        FIXTURE_IP,
        _result("abuseipdb", {"data": {"abuseConfidenceScore": 1}}),
        _settings("abuseipdb"),
        now="2026-09-05T09:00:00Z",
    )
    assert entry is not None
    assert storage.get_enrichment_record("ip", FIXTURE_IP, allow_stale=True) is None
    assert "session_id" not in entry
    assert "event_id" not in entry
    assert "payload" not in entry
    assert entry["schema_version"] == SOURCE_IP_CACHE_SCHEMA


def test_cached_session_join_is_a_bounded_reference_without_source_ip_value(tmp_path: Path) -> None:
    from production.enrichment.external_ti_session import build_session_ti_projection
    from production.utils.serialization import utc_now

    config = _source_config(tmp_path)
    worker = EnrichmentWorker(config, providers=[])
    worker.source_ip_cache.store_result(
        "abuseipdb",
        FIXTURE_IP,
        _result("abuseipdb", {"data": {"abuseConfidenceScore": 5}}),
        _settings("abuseipdb"),
        now=utc_now(),
    )
    worker.storage.save_session(
        {
            "session_id": "cache-session",
            "src_ip": FIXTURE_IP,
            "start_time": "2026-09-05T09:00:00Z",
            "is_ended": True,
        }
    )
    worker.storage.record_observable_sighting(
        {
            "sighting_id": "cache-sighting",
            "observable_type": "ip",
            "observable_value": FIXTURE_IP,
            "role": "source_ip",
            "source": "cowrie_event",
            "session_id": "cache-session",
            "event_id": "cache-event",
            "eventid": "cowrie.session.connect",
            "sensor_id": "cache-sensor",
            "timestamp": "2026-09-05T09:00:01Z",
            "payload": {"role": "source_ip", "source": "cowrie_event"},
        }
    )
    projection = build_session_ti_projection(worker.storage, "cache-session", config=config)
    assert projection["source_ip_cache"]
    assert projection["source_ip_cache"][0]["provider"] == "abuseipdb"
    assert projection["source_ip_cache"][0]["authority"] == "NON_AUTHORITATIVE_CACHE"
    encoded = json.dumps(projection, sort_keys=True)
    assert FIXTURE_IP not in encoded
    assert "session_id" not in json.dumps(projection["source_ip_cache"])


def test_cache_contract_constants_are_explicit() -> None:
    assert SOURCE_IP_CACHE_COLLECTION == "external_ti_source_ip_cache"
    assert SOURCE_IP_CACHE_SCHEMA == "external_ti_source_ip_cache.v1"
    assert MAX_CACHE_HOSTNAMES == 32
    assert MAX_CACHE_PORTS == 256
    assert MAX_CACHE_TAGS == 32
    assert MAX_CACHE_SERVICES == 64
    assert MAX_NORMALIZED_CACHE_CONTEXT_BYTES == 8_192
    assert MAX_NORMALIZED_CACHE_ENTRY_BYTES == 16_384


def test_positive_and_negative_windows_enforce_policy_minimum(tmp_path: Path) -> None:
    del tmp_path
    settings = _settings("shodan_official")
    settings.update({"refresh_window_seconds": 1, "negative_cache_seconds": 1})
    positive = build_source_ip_cache_entry(
        "shodan_official",
        FIXTURE_IP,
        _result("shodan_official", {"ports": [443]}),
        settings,
        now="2026-09-05T09:00:00Z",
    )
    negative = build_source_ip_cache_entry(
        "shodan_official",
        FIXTURE_IP,
        _result("shodan_official", {}, status="not_found"),
        settings,
        now="2026-09-05T09:00:00Z",
    )
    assert positive is not None
    assert negative is not None
    assert positive["expires_at"] == "2026-09-06T09:00:00+00:00"
    assert negative["negative_cache_until"] == "2026-09-06T09:00:00+00:00"


def test_cache_backend_exception_type_is_not_provider_error() -> None:
    assert issubclass(SourceIPCacheUnavailable, RuntimeError)
    with pytest.raises(SourceIPCacheUnavailable):
        SourceIPCacheService(object()).lookup("abuseipdb", FIXTURE_IP)


def test_unsupported_result_does_not_create_a_cache_row(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    entry = build_source_ip_cache_entry(
        "abuseipdb",
        FIXTURE_IP,
        ProviderResult("abuseipdb", "cached"),
        _settings("abuseipdb"),
    )
    assert entry is None
    assert storage.list_rows(SOURCE_IP_CACHE_COLLECTION) == []
