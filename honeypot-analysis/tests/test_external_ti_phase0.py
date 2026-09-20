from __future__ import annotations

import json
import hashlib
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from production.api.monitor_web import MonitorConfig, load_session_ti
from production.enrichment.enrichment_providers import (
    EnrichmentProvider,
    OTXProvider,
    ProviderResult,
    ShodanInternetDBProvider,
    ShodanOfficialProvider,
    build_default_providers,
    merge_provider_results,
)
from production.enrichment.external_ti_contract import (
    EXTERNAL_TI_EVIDENCE_SCHEMA,
    SOURCE_IP_AMENDMENT_SHA256,
    SOURCE_IP_ENRICHMENT_MODE,
    SOURCE_IP_POLICY_ID,
    SOURCE_IP_POLICY_VERSION,
    ProviderPacingBudget,
    build_external_ti_evidence,
    default_external_ti_provider_configs,
    evaluate_outbound_sighting,
    load_source_ip_governance_amendment,
    normalize_provider_extension,
    parse_retry_after,
    parse_source_ip_cutoff_utc,
    provider_activation_gate,
    validate_fixed_endpoint_url,
)
from production.enrichment.external_ti_session import build_session_ti_projection
from production.storage.backend import SQLiteStorage
from production.utils.config import ProductionConfig
from production.workers.enrichment_worker import EnrichmentWorker


SHA256 = "a" * 64


def _valid_sighting(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "sighting_id": "sighting-phase0",
        "observable_id": "observable-phase0",
        "observable_type": "hash",
        "observable_value": SHA256,
        "role": "file_hash",
        "source": "cowrie_event",
        "session_id": "session-phase0",
        "payload": {"metadata": {"field": "sha256", "hash_type": "sha256"}},
    }
    value.update(overrides)
    return value


def _enabled_fake_config(tmp_path):
    providers = default_external_ti_provider_configs()
    for name in ("virustotal", "otx"):
        providers[name].update(
            {
                "enabled": True,
                "minute_limit": 10,
                "daily_budget": 20,
            }
        )
    return ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        external_enrichment_profile="non_ip_observables",
        external_ti_enabled=True,
        external_ti_provider_allowlist=["virustotal", "otx"],
        external_ti_provider_configs=providers,
    )


class _FakeProvider(EnrichmentProvider):
    external = True
    requires_credential = False

    def __init__(self, name: str, statuses: list[str]) -> None:
        self.name = name
        self.supported_types = {"hash"}
        self.statuses = list(statuses)
        self.calls = 0

    def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
        self.calls += 1
        status = self.statuses[min(self.calls - 1, len(self.statuses) - 1)]
        data = {}
        if status == "ok" and self.name == "virustotal":
            data = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 1, "undetected": 3},
                        "meaningful_name": "bounded-test-family",
                    }
                }
            }
        return ProviderResult(self.name, status, data, ttl_seconds=3600)


SOURCE_IP_POLICY_PATH = Path(__file__).resolve().parents[1] / "configs" / "external_ti_source_ip_governance_amendment.v1.json"
SOURCE_IP_CUTOFF = "2026-09-05T08:00:00Z"


def _valid_source_ip_sighting(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "sighting_id": "sighting-source-ip",
        "observable_id": "observable-source-ip",
        "observable_type": "ip",
        "observable_value": "8.8.8.8",
        "role": "source_ip",
        "source": "cowrie_event",
        "session_id": "session-source-ip",
        "sensor_id": "sensor-source-ip",
        "event_id": "event-source-ip",
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-09-05T08:00:01Z",
        "payload": {
            "role": "source_ip",
            "source": "cowrie_event",
            "metadata": {"is_public": True},
        },
    }
    value.update(overrides)
    return value


def _source_ip_config(tmp_path, *, cutoff: str = SOURCE_IP_CUTOFF):
    providers = default_external_ti_provider_configs()
    providers["abuseipdb"].update(
        {"enabled": True, "minute_limit": 1, "daily_budget": 1}
    )
    return ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'source-ip.db'}",
        external_enrichment_profile="source_ip_observables",
        external_ti_enabled=True,
        external_ti_provider_allowlist=["abuseipdb"],
        external_ti_provider_configs=providers,
        source_ip_enrichment_mode=SOURCE_IP_ENRICHMENT_MODE,
        source_ip_enrichment_not_before_utc=cutoff,
        source_ip_enrichment_cutoff_operator="release-preparation-test",
        source_ip_governance_path=str(SOURCE_IP_POLICY_PATH),
        source_ip_governance_sha256=SOURCE_IP_AMENDMENT_SHA256,
        external_ti_proof_campaign_id="phase0-test-campaign",
        external_ti_proof_guard_mode="REAL_PROOF",
    )


def test_phase0_defaults_disable_every_real_provider(tmp_path) -> None:
    config = ProductionConfig(database_url=f"sqlite:///{tmp_path / 'state.db'}")
    providers = build_default_providers(config)

    assert config.external_ti_enabled is False
    assert config.external_enrichment_profile == "disabled"
    assert config.external_ti_provider_allowlist == []
    assert all(not item["enabled"] for item in config.external_ti_provider_configs.values())
    assert all(item["minute_limit"] == 0 and item["daily_budget"] == 0 for item in config.external_ti_provider_configs.values())
    assert all(not provider.enabled for provider in providers if hasattr(provider, "enabled"))


def test_builtin_http_provider_reports_credential_presence_to_activation_gate() -> None:
    assert OTXProvider(api_key="configured-test-value").credential_present is True
    assert OTXProvider(api_key="").credential_present is False


def test_session_worker_credential_gate_accepts_configured_builtin_key(tmp_path) -> None:
    config = _source_ip_config(tmp_path)
    config.abuseipdb_api_key = "configured-test-value"
    providers = build_default_providers(config)
    provider = next(item for item in providers if item.name == "abuseipdb")

    assert EnrichmentWorker._credential_present(provider) is True


@pytest.mark.parametrize(
    "sighting,expected_code",
    [
        (_valid_sighting(), "eligible_file_sha256"),
        (_valid_sighting(role="command_hash"), "role_prohibited"),
        (_valid_sighting(source="session_close"), "source_prohibited"),
        (_valid_sighting(observable_value="g" * 64), "invalid_sha256"),
        (_valid_sighting(payload={"metadata": {"field": "sha1", "hash_type": "sha1"}}), "algorithm_prohibited"),
        ({"observable_type": "ip", "observable_value": "198.51.100.2", "role": "source_ip", "source": "cowrie_event"}, "source_ip_policy_prohibited"),
        ({"observable_type": "domain", "observable_value": "example.invalid", "role": "command_domain", "source": "cowrie_event"}, "observable_type_disabled"),
    ],
)
def test_file_sha256_outbound_eligibility_is_strict(sighting, expected_code) -> None:
    decision = evaluate_outbound_sighting(sighting)
    assert decision.code == expected_code
    assert decision.eligible is (expected_code == "eligible_file_sha256")


def test_provider_activation_requires_every_explicit_gate(tmp_path) -> None:
    config = _enabled_fake_config(tmp_path)
    settings = config.external_ti_provider_configs["virustotal"]
    allowed = provider_activation_gate(
        provider="virustotal",
        config=config,
        provider_config_value=settings,
        sighting=_valid_sighting(),
        credential_present=False,
        credential_required=False,
    )
    assert allowed.eligible

    config.external_ti_enabled = False
    blocked = provider_activation_gate(
        provider="virustotal",
        config=config,
        provider_config_value=settings,
        sighting=_valid_sighting(),
        credential_present=False,
        credential_required=False,
    )
    assert blocked.code == "global_disabled"


def test_retry_after_is_bounded_and_deterministic() -> None:
    now = datetime(2026, 9, 3, tzinfo=timezone.utc)
    assert parse_retry_after("15", now) == 15
    assert parse_retry_after("999999999", now) == 30 * 24 * 60 * 60
    assert parse_retry_after("Wed, 03 Sep 2026 00:00:00 GMT", now) == 0
    assert parse_retry_after("not-a-date", now) is None


@pytest.mark.parametrize(
    ("status_code", "expected_status"),
    [(401, "auth_disabled"), (403, "auth_disabled"), (404, "not_found")],
)
def test_non_retryable_provider_http_statuses_are_single_attempt(
    status_code: int,
    expected_status: str,
) -> None:
    calls = 0

    def transport(request, **_kwargs):
        nonlocal calls
        calls += 1
        raise urllib.error.HTTPError(request.full_url, status_code, "fake response", {}, None)

    provider = OTXProvider(
        api_key="fake-unit-test-key",
        retries=2,
        retry_delay_seconds=0,
        transport=transport,
    )
    result = provider.enrich("hash", SHA256)

    assert calls == 1
    assert result.status == expected_status


def test_retry_after_prevents_early_fake_retry() -> None:
    calls = 0

    def transport(request, **_kwargs):
        nonlocal calls
        calls += 1
        raise urllib.error.HTTPError(
            request.full_url,
            429,
            "fake response",
            {"Retry-After": "60"},
            None,
        )

    provider = OTXProvider(
        api_key="fake-unit-test-key",
        retries=2,
        retry_delay_seconds=0,
        transport=transport,
    )
    result = provider.enrich("hash", SHA256)

    assert calls == 1
    assert result.status == "rate_limited"
    assert result.retry_after_seconds == 60


def test_provider_pacing_budget_denies_zero_and_consumes_attempts() -> None:
    current = [1_000.0]
    budget = ProviderPacingBudget(clock=lambda: current[0])
    assert budget.reserve("virustotal", minute_limit=0, daily_budget=0).status == "budget_exhausted"
    assert budget.reserve("virustotal", minute_limit=1, daily_budget=2).allowed
    limited = budget.reserve("virustotal", minute_limit=1, daily_budget=2)
    assert limited.status == "rate_limited"
    current[0] += 61
    assert budget.reserve("virustotal", minute_limit=1, daily_budget=2).allowed
    current[0] += 61
    assert budget.reserve("virustotal", minute_limit=1, daily_budget=2).status == "budget_exhausted"


def test_builtin_provider_budget_is_reserved_for_each_fake_retry_attempt(tmp_path) -> None:
    calls = []

    class _Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return b'{"pulse_info":{"pulses":[]}}'

    def transport(request, **_kwargs):
        calls.append(request.full_url)
        if len(calls) == 1:
            raise urllib.error.HTTPError(request.full_url, 500, "fake retry", {}, None)
        return _Response()

    config = _enabled_fake_config(tmp_path)
    provider = OTXProvider(
        api_key="fake-unit-test-key",
        retries=1,
        retry_delay_seconds=0,
        endpoint_id=config.external_ti_provider_configs["otx"]["endpoint_id"],
        transport=transport,
    )
    provider.credential_present = True
    worker = EnrichmentWorker(config, providers=[provider])

    results = worker._run_providers("hash", SHA256, sighting=_valid_sighting())

    assert len(calls) == 2
    assert results[0].status == "ok"
    assert results[0].attempt_count == 2
    assert results[0].budget_consumed == 2
    assert worker.pacing.snapshot("otx")["attempts_today"] == 2


def test_provider_isolation_preserves_success_while_retrying_failure(tmp_path) -> None:
    config = _enabled_fake_config(tmp_path)
    vt = _FakeProvider("virustotal", ["ok"])
    otx = _FakeProvider("otx", ["temporary_error", "ok"])
    worker = EnrichmentWorker(config, providers=[vt, otx])

    first = worker._run_providers("hash", SHA256, sighting=_valid_sighting())
    payload, statuses, expires = merge_provider_results(
        "hash", SHA256, first, default_ttl_seconds=3600
    )
    worker.storage.save_enrichment_record("hash", SHA256, payload, statuses, expires)
    stored = worker.storage.get_enrichment_record("hash", SHA256, allow_stale=True)
    second = worker._run_providers(
        "hash", SHA256, sighting=_valid_sighting(), existing_record=stored
    )

    assert vt.calls == 1
    assert otx.calls == 2
    assert {item.provider: item.status for item in second} == {
        "virustotal": "cached",
        "otx": "ok",
    }
    assert stored is not None
    assert stored["provider_status"]["virustotal"]["status"] == "ok"

    second_payload, second_status, _ = merge_provider_results(
        "hash",
        SHA256,
        second,
        default_ttl_seconds=3600,
        existing_payload=stored["payload"],
        existing_provider_status=stored["provider_status"],
    )
    assert second_status["virustotal"]["status"] == "cached"
    assert second_payload["provider_evidence"]["virustotal"]["finding_state"] == "DETECTIONS_PRESENT"


def test_session_evidence_rejects_authority_and_raw_provider_fields() -> None:
    evidence = build_external_ti_evidence(
        session_id="session-phase0",
        observable_type="hash",
        observable_value=SHA256,
        sightings=[_valid_sighting()],
        provider="virustotal",
        provider_evidence={
            "authority": "AUTHORITATIVE",
            "finding_state": "trusted",
            "lookup_status": "trusted",
            "endpoint_id": "https://user-controlled.invalid/steal",
            "normalized_extension": {
                "malicious": 1,
                "raw_provider_json": {"password": "must-not-survive"},
                "per_engine_results": ["must-not-survive"],
            },
            "normalized_result": {"FINAL_S1": "promote"},
            "trusted_attack_techniques": ["T1059"],
            "response_authority": "auto",
            "requires_manual_approval": False,
            "safe_to_auto_execute": True,
            "api_key": "must-not-survive",
        },
    )

    encoded = json.dumps(evidence, sort_keys=True)
    assert evidence["authority"] == "NON_AUTHORITATIVE_CONTEXT_ONLY"
    assert evidence["finding_state"] == "UNKNOWN"
    assert evidence["lookup_status"] == "UNAVAILABLE"
    assert evidence["endpoint_id"] == ""
    assert "raw_provider_json" not in encoded
    assert "per_engine_results" not in encoded
    assert "FINAL_S1" not in encoded
    assert "trusted_attack_techniques" not in encoded
    assert "response_authority" not in encoded
    assert "must-not-survive" not in encoded


def test_session_projection_joins_only_exact_file_sha256(tmp_path) -> None:
    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'state.db'}")
    storage.initialize()
    for session_id in ("session-a", "session-b"):
        storage.save_session(
            {
                "session_id": session_id,
                "src_ip": "192.0.2.10",
                "start_time": "2026-09-03T00:00:00+00:00",
                "is_ended": True,
            }
        )
        storage.record_observable_sighting(
            _valid_sighting(
                sighting_id=f"sighting-{session_id}",
                session_id=session_id,
                timestamp="2026-09-03T00:01:00+00:00",
            )
        )
    payload, statuses, expires = merge_provider_results(
        "hash",
        SHA256,
        [ProviderResult("virustotal", "not_found", ttl_seconds=3600)],
        default_ttl_seconds=3600,
    )
    storage.save_enrichment_record("hash", SHA256, payload, statuses, expires)

    response = build_session_ti_projection(storage, "session-a")
    assert response["ok"] is True
    assert response["status"] == "TI_AVAILABLE"
    assert len(response["evidence"]) == 1
    assert response["evidence"][0]["finding_state"] == "NOT_FOUND"
    assert response["evidence"][0]["authority"] == "NON_AUTHORITATIVE_CONTEXT_ONLY"
    assert response["freshness"]["state"] == "TI_FRESH"
    assert response["shared_entities"][0]["relation"] == "STRONG_SHARED_ENTITY"
    assert response["shared_entities"][0]["linked_sessions"][0]["session_id"] == "session-b"
    assert "src_ip" not in json.dumps(response)
    assert "credential" not in json.dumps(response).lower()

    storage.save_enrichment_record(
        "hash",
        SHA256,
        payload,
        statuses,
        expires_at="2000-01-01T00:00:00+00:00",
    )
    stale_response = build_session_ti_projection(storage, "session-a")
    assert stale_response["freshness"]["state"] == "TI_EXPIRED"


def test_api_session_ti_is_separate_from_primary_detail(tmp_path) -> None:
    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'state.db'}")
    storage.initialize()
    storage.save_session({"session_id": "api-session", "src_ip": "192.0.2.20"})
    config = MonitorConfig(
        db_path=str(tmp_path / "state.db"),
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        reports_dir=str(tmp_path / "reports"),
    )
    response = load_session_ti(config, "api-session", _storage=storage)
    assert response["ok"] is True
    assert response["status"] == "TI_PENDING"
    assert response["evidence"] == []


def test_default_worker_network_guard_never_reaches_urlopen(tmp_path, monkeypatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("real external provider network call")

    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    config = ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        otx_api_key="fake-config-key",
        abuseipdb_api_key="fake-config-key",
        shodan_api_key="fake-config-key",
        virustotal_api_key="fake-config-key",
        censys_api_id="fake-config-id",
        censys_api_secret="fake-config-secret",
        censys_platform_token="fake-config-token",
    )
    worker = EnrichmentWorker(config)
    results = worker._run_providers("hash", SHA256, sighting=_valid_sighting())
    assert results
    assert all(item.status in {"disabled", "not_configured", "policy_prohibited"} for item in results)


def test_fixed_provider_endpoint_rejects_redirect_or_arbitrary_host() -> None:
    validate_fixed_endpoint_url(
        "virustotal",
        "virustotal_lookup_v3",
        "https://www.virustotal.com/api/v3/files/" + SHA256,
    )
    with pytest.raises(ValueError):
        validate_fixed_endpoint_url(
            "virustotal",
            "virustotal_lookup_v3",
            "https://example.invalid/api/v3/files/" + SHA256,
        )


def test_fixed_provider_transport_is_direct_tls_and_no_redirect(monkeypatch) -> None:
    built_handlers = []

    class _Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def geturl(self):
            return "https://api.shodan.io/shodan/host/8.8.8.8?key=fake-key"

        def read(self, _limit):
            return b'{"ports":[443]}'

    class _Opener:
        def open(self, _request, timeout):
            assert timeout == 20
            return _Response()

    def fake_build_opener(*handlers):
        built_handlers.extend(handlers)
        return _Opener()

    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    result = ShodanOfficialProvider(
        "fake-key",
        retries=0,
        endpoint_id="shodan_host_v1",
        activation_enabled=True,
    ).enrich("ip", "8.8.8.8")
    assert result.status == "ok"

    proxy = next(item for item in built_handlers if isinstance(item, urllib.request.ProxyHandler))
    assert proxy.proxies == {}
    tls = next(item for item in built_handlers if isinstance(item, urllib.request.HTTPSHandler))
    assert tls._context.check_hostname is True
    assert tls._context.verify_mode == ssl.CERT_REQUIRED
    redirect = next(item for item in built_handlers if item.__class__.__name__ == "_NoRedirectHandler")
    with pytest.raises(urllib.error.HTTPError):
        redirect.redirect_request(
            urllib.request.Request(
                "https://api.shodan.io/shodan/host/8.8.8.8?key=fake-key"
            ),
            None,
            302,
            "redirect",
            {},
            "https://example.invalid/",
        )


def test_shodan_endpoint_contract_rejects_query_drift_and_scan_paths() -> None:
    with pytest.raises(ValueError):
        validate_fixed_endpoint_url(
            "shodan_official",
            "shodan_host_v1",
            "https://api.shodan.io/shodan/host/8.8.8.8",
        )
    with pytest.raises(ValueError):
        validate_fixed_endpoint_url(
            "shodan_official",
            "shodan_host_v1",
            "https://api.shodan.io/shodan/host/8.8.8.8?key=a&key=b",
        )
    with pytest.raises(ValueError):
        validate_fixed_endpoint_url(
            "shodan_official",
            "shodan_host_v1",
            "https://api.shodan.io/shodan/scan/8.8.8.8?key=a",
        )
    with pytest.raises(ValueError):
        validate_fixed_endpoint_url(
            "shodan_internetdb",
            "shodan_internetdb_v1",
            "https://internetdb.shodan.io/8.8.8.8?key=a",
        )


def test_shodan_disabled_modes_make_zero_requests() -> None:
    calls = []

    def forbidden(request, **_kwargs):
        calls.append(request.full_url)
        raise AssertionError("disabled Shodan mode attempted a request")

    assert ShodanOfficialProvider(
        "fake-key", transport=forbidden, activation_enabled=False
    ).enrich("ip", "8.8.8.8").status == "not_configured"
    assert ShodanInternetDBProvider(
        transport=forbidden, activation_enabled=False
    ).enrich("ip", "8.8.8.8").status == "not_configured"
    assert calls == []


def test_source_ip_amendment_is_hash_bound_and_secret_free() -> None:
    amendment = load_source_ip_governance_amendment(str(SOURCE_IP_POLICY_PATH))
    assert amendment.policy_id == SOURCE_IP_POLICY_ID
    assert amendment.version == SOURCE_IP_POLICY_VERSION
    assert amendment.sha256 == SOURCE_IP_AMENDMENT_SHA256
    assert amendment.allowed_outbound_fields == ("normalized_source_ip",)
    assert amendment.canonical_mongodb_enrichment_record_write is False
    assert amendment.authorizes_provider("abuseipdb")
    assert amendment.authorizes_provider("shodan_official")
    assert not amendment.authorizes_provider("virustotal")


def test_source_ip_amendment_missing_and_malformed_fail_closed(tmp_path) -> None:
    with pytest.raises(ValueError):
        load_source_ip_governance_amendment(str(tmp_path / "missing.json"))
    malformed = tmp_path / "malformed.json"
    malformed.write_text("not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        load_source_ip_governance_amendment(
            str(malformed),
            expected_sha256=hashlib.sha256(malformed.read_bytes()).hexdigest(),
        )


@pytest.mark.parametrize(
    "overrides,expected_code",
    [
        ({"observable_value": "10.0.0.8"}, "source_ip_not_public"),
        ({"observable_value": "127.0.0.1"}, "source_ip_not_public"),
        ({"observable_value": "169.254.1.2"}, "source_ip_not_public"),
        ({"observable_value": "not-an-ip"}, "invalid_source_ip"),
        ({"role": "destination_ip"}, "role_prohibited"),
        ({"source": "session_close"}, "source_prohibited"),
        ({"timestamp": "2026-09-05T07:59:59Z"}, "source_ip_before_cutoff"),
        ({"timestamp": "2026-09-05T08:00:00"}, "source_ip_timestamp_missing_or_malformed"),
    ],
)
def test_source_ip_policy_gate_is_public_provenance_and_cutoff_bound(
    overrides, expected_code
) -> None:
    amendment = load_source_ip_governance_amendment(str(SOURCE_IP_POLICY_PATH))
    decision = evaluate_outbound_sighting(
        _valid_source_ip_sighting(**overrides),
        provider="abuseipdb",
        source_ip_governance=amendment,
        source_ip_cutoff_utc=parse_source_ip_cutoff_utc(SOURCE_IP_CUTOFF),
    )
    assert decision.code == expected_code
    assert not decision.eligible


def test_source_ip_post_cutoff_is_eligible_only_for_authorized_provider() -> None:
    amendment = load_source_ip_governance_amendment(str(SOURCE_IP_POLICY_PATH))
    allowed = evaluate_outbound_sighting(
        _valid_source_ip_sighting(),
        provider="shodan_internetdb",
        source_ip_governance=amendment,
        source_ip_cutoff_utc=SOURCE_IP_CUTOFF,
    )
    assert allowed.eligible
    assert allowed.code == "eligible_source_ip"
    assert allowed.observable_value == "8.8.8.8"
    rejected = evaluate_outbound_sighting(
        _valid_source_ip_sighting(),
        provider="virustotal",
        source_ip_governance=amendment,
        source_ip_cutoff_utc=SOURCE_IP_CUTOFF,
    )
    assert rejected.code == "source_ip_policy_prohibited"


def test_source_ip_cutoff_missing_or_malformed_fails_closed() -> None:
    amendment = load_source_ip_governance_amendment(str(SOURCE_IP_POLICY_PATH))
    missing = evaluate_outbound_sighting(
        _valid_source_ip_sighting(),
        provider="abuseipdb",
        source_ip_governance=amendment,
    )
    assert missing.code == "source_ip_cutoff_missing"
    with pytest.raises(ValueError):
        parse_source_ip_cutoff_utc("2026-09-05T08:00:00+07:00")
    malformed = evaluate_outbound_sighting(
        _valid_source_ip_sighting(),
        provider="abuseipdb",
        source_ip_governance=amendment,
        source_ip_cutoff_utc="not-a-timestamp",
    )
    assert malformed.code == "source_ip_cutoff_malformed"


def test_source_ip_worker_restart_preserves_cutoff_and_rejects_historical_job(tmp_path) -> None:
    config = _source_ip_config(tmp_path)
    first = EnrichmentWorker(config, providers=[])
    second = EnrichmentWorker(config, providers=[])
    assert first.source_ip_cutoff_utc == second.source_ip_cutoff_utc

    class _SourceProvider(EnrichmentProvider):
        external = True
        requires_credential = False
        name = "abuseipdb"
        supported_types = {"ip"}

        def __init__(self):
            self.calls = 0

        def enrich(self, observable_type, observable_value):
            self.calls += 1
            return ProviderResult(self.name, "ok", {"abuseConfidenceScore": 1})

    provider = _SourceProvider()
    worker = EnrichmentWorker(config, providers=[provider])
    storage = worker.storage
    job_id, inserted = storage.enqueue_enrichment_job(
        "ip",
        "8.8.8.8",
        session_id="session-source-ip",
        payload={
            "role": "source_ip",
            "source": "cowrie_event",
            "event_id": "historical-event",
            "eventid": "cowrie.session.connect",
            "sensor_id": "sensor-source-ip",
            "timestamp": "2026-09-05T07:59:59Z",
        },
    )
    assert inserted
    assert worker.process_once() == 1
    assert provider.calls == 0
    assert storage.get_enrichment_record("ip", "8.8.8.8", allow_stale=True) is None
    job = next(row for row in storage.list_rows("enrichment_jobs") if row["job_id"] == job_id)
    assert job["status"] == "succeeded"


def test_source_ip_provider_result_is_not_written_to_canonical_record(tmp_path) -> None:
    config = _source_ip_config(tmp_path)

    class _SourceProvider(EnrichmentProvider):
        external = True
        requires_credential = False
        name = "abuseipdb"
        supported_types = {"ip"}

        def __init__(self):
            self.calls = 0

        def enrich(self, observable_type, observable_value):
            self.calls += 1
            return ProviderResult(
                self.name,
                "ok",
                {"abuseConfidenceScore": 7, "totalReports": 2},
            )

    provider = _SourceProvider()
    worker = EnrichmentWorker(config, providers=[provider])
    storage = worker.storage
    job_id, inserted = storage.enqueue_enrichment_job(
        "ip",
        "8.8.8.8",
        session_id="session-source-ip",
        payload={
            "role": "source_ip",
            "source": "cowrie_event",
            "event_id": "new-event",
            "eventid": "cowrie.session.connect",
            "sensor_id": "sensor-source-ip",
            "timestamp": "2026-09-05T08:00:01Z",
        },
    )
    assert inserted
    assert worker.process_once() == 1
    assert provider.calls == 1
    assert storage.get_enrichment_record("ip", "8.8.8.8", allow_stale=True) is None
    job = next(row for row in storage.list_rows("enrichment_jobs") if row["job_id"] == job_id)
    assert job["status"] == "succeeded"


def test_enrichment_job_preserves_event_provenance_after_session_close(tmp_path) -> None:
    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'provenance.db'}")
    storage.initialize()
    event_payload = {
        "role": "source_ip",
        "source": "cowrie_event",
        "event_id": "event-provenance",
        "eventid": "cowrie.session.connect",
        "sensor_id": "sensor-provenance",
        "timestamp": "2026-09-18T00:00:01Z",
    }
    close_payload = {
        "role": "source_ip",
        "source": "session_close",
        "session_id": "session-provenance",
    }

    job_id, inserted = storage.enqueue_enrichment_job(
        "ip",
        "198.51.100.77",
        session_id="session-provenance",
        payload=event_payload,
    )
    assert inserted
    duplicate_id, queued = storage.enqueue_enrichment_job(
        "ip",
        "198.51.100.77",
        session_id="session-provenance",
        payload=close_payload,
    )
    assert duplicate_id == job_id
    assert queued

    claimed = storage.claim_enrichment_jobs("provenance-test", 1, 30, 3)
    assert len(claimed) == 1
    assert claimed[0]["payload"] == event_payload | {
        "observable_type": "ip",
        "observable_value": "198.51.100.77",
        "session_id": "session-provenance",
    }


def test_enrichment_job_upgrades_session_close_to_event_provenance(tmp_path) -> None:
    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'provenance-reverse.db'}")
    storage.initialize()
    close_payload = {
        "role": "source_ip",
        "source": "session_close",
        "session_id": "session-provenance-reverse",
    }
    event_payload = {
        "role": "source_ip",
        "source": "cowrie_event",
        "event_id": "event-provenance-reverse",
        "eventid": "cowrie.session.connect",
        "sensor_id": "sensor-provenance",
        "timestamp": "2026-09-18T00:00:02Z",
    }

    storage.enqueue_enrichment_job(
        "ip",
        "198.51.100.78",
        session_id="session-provenance-reverse",
        payload=close_payload,
    )
    storage.enqueue_enrichment_job(
        "ip",
        "198.51.100.78",
        session_id="session-provenance-reverse",
        payload=event_payload,
    )

    claimed = storage.claim_enrichment_jobs("provenance-test", 1, 30, 3)
    assert len(claimed) == 1
    assert claimed[0]["payload"]["source"] == "cowrie_event"
    assert claimed[0]["payload"]["event_id"] == "event-provenance-reverse"


def test_source_ip_config_requires_durable_cutoff(tmp_path) -> None:
    providers = default_external_ti_provider_configs()
    providers["abuseipdb"].update({"enabled": True, "minute_limit": 1, "daily_budget": 1})
    with pytest.raises(ValueError, match="cutoff"):
        ProductionConfig(
            database_url=f"sqlite:///{tmp_path / 'invalid.db'}",
            external_enrichment_profile="source_ip_observables",
            external_ti_enabled=True,
            external_ti_provider_allowlist=["abuseipdb"],
            external_ti_provider_configs=providers,
            source_ip_enrichment_mode=SOURCE_IP_ENRICHMENT_MODE,
        )


def test_abuseipdb_preserves_key_header_and_normalized_ip_only() -> None:
    calls = []

    class _Response:
        headers = {"Content-Length": "20"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return b'{"data":{"totalReports":2}}'

    def transport(request, **_kwargs):
        calls.append(request)
        return _Response()

    from production.enrichment.enrichment_providers import AbuseIPDBProvider

    provider = AbuseIPDBProvider("fake-abuse-key", retries=0, transport=transport)
    result = provider.enrich("ip", "8.8.8.8")
    assert result.status == "ok"
    assert len(calls) == 1
    request = calls[0]
    assert "api.abuseipdb.com/api/v2/check" in request.full_url
    assert "ipAddress=8.8.8.8" in request.full_url
    assert request.get_header("Key") == "fake-abuse-key"
    assert "/report" not in request.full_url
    assert "fake-abuse-key" not in json.dumps(result.to_status(), sort_keys=True)


def test_shodan_official_query_key_is_fixed_and_errors_are_redacted() -> None:
    captured = []

    class _Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return b'{"ports":[22],"org":"bounded"}'

    def transport(request, **_kwargs):
        captured.append(request)
        return _Response()

    provider = ShodanOfficialProvider("fake-shodan-key", retries=0, transport=transport)
    result = provider.enrich("ip", "8.8.8.8")
    assert result.status == "ok"
    assert captured[0].full_url == "https://api.shodan.io/shodan/host/8.8.8.8?key=fake-shodan-key"
    assert "fake-shodan-key" not in json.dumps(result.to_status(), sort_keys=True)

    def failing_transport(request, **_kwargs):
        raise RuntimeError(f"request={request.full_url}")

    failed = ShodanOfficialProvider(
        "fake-shodan-key", retries=0, transport=failing_transport
    ).enrich("ip", "8.8.8.8")
    assert failed.status == "permanent_error"
    assert "fake-shodan-key" not in failed.error
    assert "fake-shodan-key" not in json.dumps(failed.to_status(), sort_keys=True)


def test_shodan_official_does_not_fallback_and_internetdb_is_explicit() -> None:
    official_calls = []

    def failing_transport(request, **_kwargs):
        official_calls.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, 500, "fake", {}, None)

    failed = ShodanOfficialProvider(
        "fake-shodan-key", retries=0, transport=failing_transport
    ).enrich("ip", "8.8.8.8")
    assert failed.status == "temporary_error"
    assert len(official_calls) == 1
    assert all("internetdb.shodan.io" not in value for value in official_calls)

    internetdb_calls = []

    class _Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return b'{"ports":[80],"hostnames":["bounded.example"]}'

    def internetdb_transport(request, **_kwargs):
        internetdb_calls.append(request.full_url)
        return _Response()

    internetdb = ShodanInternetDBProvider(
        retries=0, transport=internetdb_transport, activation_enabled=True
    ).enrich("ip", "8.8.8.8")
    assert internetdb.status == "ok"
    assert internetdb_calls == ["https://internetdb.shodan.io/8.8.8.8"]
    assert internetdb.provider == "shodan_internetdb"


def test_shodan_normalized_output_is_bounded_and_raw_response_is_not_persisted() -> None:
    result = ProviderResult(
        "shodan_official",
        "ok",
        {
            "asn": "AS64500",
            "org": "bounded-org",
            "ports": list(range(1, 400)),
            "data": [{"banner": "secret-banner", "port": 22}],
            "hostnames": ["h" * 500] * 100,
        },
    )
    payload, status, _ = merge_provider_results("ip", "8.8.8.8", [result])
    encoded = json.dumps({"payload": payload, "status": status}, sort_keys=True)
    assert payload["shodan_provider"] == "shodan_official"
    assert payload["shodan_context_source"] == "shodan_official"
    assert len(payload["open_ports"]) == 256
    assert len(payload["shodan_hostnames"][0]) == 253
    assert "secret-banner" not in encoded
    assert "data" not in status["shodan_official"]["provider_evidence"]["normalized_extension"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ports", None),
        ("ports", {}),
        ("ports", "443"),
        ("ports", 443),
        ("hostnames", None),
        ("hostnames", {}),
        ("tags", None),
        ("tags", {}),
        ("org", {"unexpected": "mapping"}),
        ("organization", {"unexpected": "mapping"}),
        ("isp", ["unexpected"]),
        ("last_update", {"unexpected": "mapping"}),
        ("services", {"unexpected": "mapping"}),
        ("data", {"unexpected": "mapping"}),
    ],
)
def test_shodan_optional_field_variance_is_fail_soft(field, value) -> None:
    response = {
        "org": "fixture-organization",
        "organization": "fixture-organization-fallback",
        "ports": [22, "443", "invalid"],
        "hostnames": ["fixture.example"],
        "tags": ["fixture-tag"],
        "last_update": "2026-09-05T00:00:00Z",
    }
    response[field] = value

    _, extension, finding, _, _, _ = normalize_provider_extension(
        "shodan_official", response
    )

    assert finding == "CONTEXT_PRESENT"
    assert extension["organization"] in {
        "fixture-organization",
        "fixture-organization-fallback",
    }
    assert extension["organization"] in json.dumps(extension, sort_keys=True)
    assert all(len(str(item)) <= 96 for item in extension.get("normalization_diagnostics", []))


def test_shodan_empty_fields_and_last_update_aliases_are_supported() -> None:
    for response in (
        {"organization": "fixture-organization", "hostnames": [], "tags": []},
        {
            "organization": "fixture-organization",
            "hostnames": [],
            "tags": [],
            "last_seen": "2026-09-05T00:00:01Z",
        },
        {
            "organization": "fixture-organization",
            "hostnames": [],
            "tags": [],
            "last_update": 1725494400,
        },
    ):
        _, extension, finding, _, _, _ = normalize_provider_extension(
            "shodan_official", response
        )
        assert finding == "CONTEXT_PRESENT"
        assert extension["hostnames"] == []
        assert extension["tags"] == []

    assert extension["last_update"] == "1725494400"


def test_shodan_missing_organization_and_isp_is_still_bounded() -> None:
    _, extension, finding, _, _, _ = normalize_provider_extension(
        "shodan_official", {"ports": [443]}
    )
    assert finding == "CONTEXT_PRESENT"
    assert extension["organization"] is None
    assert extension["isp"] is None
    assert extension["ports"] == [443]


def test_shodan_404_is_no_data_without_retry_or_fallback() -> None:
    calls = []

    def transport(request, **_kwargs):
        calls.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, 404, "fixture no data", {}, None)

    result = ShodanOfficialProvider(
        "fake-shodan-key",
        retries=0,
        endpoint_id="shodan_host_v1",
        transport=transport,
    ).enrich("ip", "8.8.8.8")
    assert result.status == "not_found"
    assert len(calls) == 1
    assert all("internetdb.shodan.io" not in value for value in calls)


def test_shodan_service_projection_is_bounded_and_never_copies_banners() -> None:
    _, extension, finding, _, _, _ = normalize_provider_extension(
        "shodan_official",
        {
            "organization": "fixture-organization",
            "ports": [22, "443", "not-a-port"],
            "data": [
                {"product": "OpenSSH", "port": 22, "banner": "fixture-banner-a"},
                {
                    "_shodan": {"module": "nginx"},
                    "port": "443",
                    "banner": "fixture-banner-b",
                },
                {
                    "service_name": "http",
                    "representative_info": {"sampled_port": 8080},
                    "banner": "fixture-banner-c",
                },
                {"product": {"unexpected": "mapping"}, "banner": "fixture-banner-d"},
                {"banner": "fixture-banner-only"},
            ],
        },
    )

    assert finding == "CONTEXT_PRESENT"
    assert extension["ports"] == [22, 443]
    assert extension["service_product_summary"] == [
        "OpenSSH 22",
        "nginx 443",
        "http 8080",
    ]
    encoded = json.dumps(extension, sort_keys=True)
    assert "fixture-banner" not in encoded
    assert "data" not in extension
    assert len(extension["service_product_summary"]) <= 64


def test_shodan_empty_or_banner_only_200_is_bounded_normalization_failure() -> None:
    for response in ({}, {"data": []}, {"data": [{"banner": "fixture-only"}]}):
        _, extension, finding, _, _, _ = normalize_provider_extension(
            "shodan_official", response
        )
        assert finding == "NO_ADDITIONAL_CONTEXT"
        assert "fixture-only" not in json.dumps(extension, sort_keys=True)

    class _Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return b'{"data":[{"banner":"fixture-secret-banner"}]}'

    provider = ShodanOfficialProvider(
        "fake-shodan-key",
        retries=0,
        endpoint_id="shodan_host_v1",
        transport=lambda request, **_kwargs: _Response(),
    )
    result = provider.enrich("ip", "8.8.8.8")
    assert result.status == "malformed_response"
    assert "fixture-secret-banner" not in result.error
    assert "fixture-secret-banner" not in json.dumps(result.to_status(), sort_keys=True)


def test_source_ip_provider_controls_are_distinct_and_cache_windows_are_bounded() -> None:
    configs = default_external_ti_provider_configs()
    for provider in ("abuseipdb", "shodan_official"):
        assert configs[provider]["max_attempts"] == 1
        assert configs[provider]["max_new_requests"] == 1
        assert configs[provider]["refresh_window_seconds"] >= 86400
        assert configs[provider]["negative_cache_seconds"] >= 86400
    assert configs["shodan_official"]["mode"] == "official_lookup"
    assert configs["shodan_internetdb"]["mode"] == "internetdb_lookup"
    assert configs["shodan_official"]["endpoint_id"] != configs["shodan_internetdb"]["endpoint_id"]


def test_source_ip_provider_cache_is_provider_specific_and_preserves_negative_results() -> None:
    fetched_at = "2026-09-05T00:00:00+00:00"
    payload, statuses, _ = merge_provider_results(
        "ip",
        "198.51.100.8",
        [
            ProviderResult(
                "abuseipdb", "not_found", ttl_seconds=86400, fetched_at=fetched_at
            ),
            ProviderResult(
                "shodan_official", "not_found", ttl_seconds=86400, fetched_at=fetched_at
            ),
        ],
        default_ttl_seconds=86400,
    )

    cache = payload["provider_cache"]
    assert {key.split("|", 1)[0] for key in cache} == {"abuseipdb", "shodan_official"}
    assert statuses["abuseipdb"]["status"] == "not_found"
    assert statuses["shodan_official"]["status"] == "not_found"
    assert statuses["shodan_official"]["provider_evidence"]["finding_state"] == "NOT_FOUND"
    assert statuses["shodan_official"]["ttl_seconds"] >= 86400

    cached_payload, cached_statuses, _ = merge_provider_results(
        "ip",
        "198.51.100.8",
        [ProviderResult("shodan_official", "cached", fetched_at=fetched_at)],
        existing_payload=payload,
        existing_provider_status=statuses,
    )
    assert cached_statuses["shodan_official"]["status"] == "cached"
    assert cached_statuses["shodan_official"]["provider_evidence"]["finding_state"] == "NOT_FOUND"
    assert {key.split("|", 1)[0] for key in cached_payload["provider_cache"]} == {
        "abuseipdb",
        "shodan_official",
    }


@pytest.mark.parametrize(
    ("abuse_status", "shodan_status"),
    [("temporary_error", "ok"), ("ok", "not_found")],
)
def test_source_ip_provider_failures_are_independent(
    tmp_path, abuse_status, shodan_status
) -> None:
    config = _source_ip_config(tmp_path)
    provider_configs = config.external_ti_provider_configs
    for name in ("abuseipdb", "shodan_official"):
        provider_configs[name].update(
            {"enabled": True, "minute_limit": 1, "daily_budget": 1}
        )
    config.external_ti_provider_allowlist = ["abuseipdb", "shodan_official"]

    class _SourceProvider(EnrichmentProvider):
        external = True
        requires_credential = False
        supported_types = {"ip"}

        def __init__(self, name, status):
            self.name = name
            self.status = status
            self.calls = 0

        def enrich(self, observable_type, observable_value):
            self.calls += 1
            data = {"ports": [443]} if self.status == "ok" and self.name == "shodan_official" else {}
            return ProviderResult(self.name, self.status, data=data, ttl_seconds=86400)

    abuse = _SourceProvider("abuseipdb", abuse_status)
    shodan = _SourceProvider("shodan_official", shodan_status)
    worker = EnrichmentWorker(config, providers=[abuse, shodan])
    results = worker._run_providers(
        "ip", "8.8.8.8", sighting=_valid_source_ip_sighting()
    )

    assert abuse.calls == 1
    assert shodan.calls == 1
    assert {item.provider: item.status for item in results} == {
        "abuseipdb": abuse_status,
        "shodan_official": shodan_status,
    }


def test_event_source_ip_queue_payload_is_minimized_to_governed_metadata(tmp_path) -> None:
    from production.enrichment.enrichment_cache import enqueue_event_observables

    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'state.db'}")
    storage.initialize()
    count = enqueue_event_observables(
        storage,
        {
            "src_ip": "8.8.8.8",
            "session": "fixture-session",
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-09-05T00:00:00Z",
            "input": "fixture-command",
            "password": "fixture-password",
        },
        event_id="fixture-event",
        sensor_id="fixture-sensor",
    )
    assert count == 1
    job = storage.list_rows("enrichment_jobs", limit=1)[0]
    payload = json.loads(job["payload_json"])
    assert set(payload) <= {
        "source",
        "role",
        "event_id",
        "eventid",
        "sensor_id",
        "timestamp",
        "observable_type",
        "observable_value",
        "session_id",
    }
    assert "fixture-command" not in json.dumps(payload)
    assert "fixture-password" not in json.dumps(payload)
