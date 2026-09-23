from __future__ import annotations

import json
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from production.api.monitor_web import (
    MonitorConfig,
    load_observable_ti,
    load_source_ip_pivot,
)
from production.enrichment.enrichment_providers import ProviderResult, merge_provider_results
from production.enrichment.enrichment_cache import SourceIPCacheService
from production.enrichment.external_ti_contract import (
    SOURCE_IP_AMENDMENT_SHA256,
    SOURCE_IP_ENRICHMENT_MODE,
    SOURCE_IP_PRODUCTION_POLICY_V2_3_VERSION,
    SOURCE_IP_PRODUCTION_POLICY_V2_4_VERSION,
    default_external_ti_provider_configs,
    evaluate_outbound_sighting,
    load_source_ip_governance_amendment,
    parse_source_ip_cutoff_utc,
)
from production.enrichment.external_ti_session import (
    OBSERVABLE_TI_SCHEMA,
    SOURCE_IP_CROSS_SESSION_SCHEMA,
    build_observable_ti_projection,
    build_session_ti_projection,
    build_source_ip_cross_session_projection,
)
from production.storage.backend import SQLiteStorage
from production.utils.config import ProductionConfig


SHA256 = "a" * 64
SOURCE_IP = "8.8.8.8"
POLICY_PATH = (
    Path(__file__).resolve().parents[1]
    / "configs"
    / "external_ti_source_ip_governance_amendment.v1.json"
)


def _source_config(tmp_path: Path) -> ProductionConfig:
    providers = default_external_ti_provider_configs()
    providers["abuseipdb"].update({"enabled": True, "minute_limit": 1, "daily_budget": 1})
    return ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        external_enrichment_profile="source_ip_observables",
        external_ti_enabled=True,
        external_ti_provider_allowlist=["abuseipdb"],
        external_ti_provider_configs=providers,
        source_ip_enrichment_mode=SOURCE_IP_ENRICHMENT_MODE,
        source_ip_enrichment_not_before_utc="2026-09-05T08:00:00Z",
        source_ip_enrichment_cutoff_operator="read-model-test",
        source_ip_governance_path=str(POLICY_PATH),
        source_ip_governance_sha256=SOURCE_IP_AMENDMENT_SHA256,
        external_ti_proof_campaign_id="read-model-test",
        external_ti_proof_guard_mode="REAL_PROOF",
    )


def _sighting(
    session_id: str,
    *,
    observable_type: str = "ip",
    observable_value: str = SOURCE_IP,
    role: str = "source_ip",
    sighting_id: str | None = None,
    timestamp: str = "2026-09-05T09:00:00Z",
) -> dict[str, object]:
    return {
        "sighting_id": sighting_id or f"{session_id}-{role}-{observable_type}",
        "observable_id": f"observable-{observable_type}",
        "observable_type": observable_type,
        "observable_value": observable_value,
        "role": role,
        "source": "cowrie_event",
        "session_id": session_id,
        "sensor_id": "sensor-read-model",
        "event_id": f"event-{session_id}",
        "eventid": "cowrie.session.connect",
        "timestamp": timestamp,
        "payload": {
            "role": role,
            "source": "cowrie_event",
            "metadata": {"field": "sha256", "hash_type": "sha256"}
            if observable_type == "hash"
            else {},
        },
    }


def _storage(tmp_path: Path) -> SQLiteStorage:
    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'state.db'}")
    storage.initialize()
    return storage


def test_session_summary_counts_types_and_keeps_hash_alias_hash_only(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    storage.save_session({"session_id": "summary-session", "src_ip": SOURCE_IP})
    storage.record_observable_sighting(_sighting("summary-session"))
    storage.record_observable_sighting(
        _sighting(
            "summary-session",
            observable_type="hash",
            observable_value=SHA256,
            role="file_hash",
            sighting_id="summary-hash",
        )
    )

    response = build_session_ti_projection(storage, "summary-session", config=_source_config(tmp_path))
    summary = response["external_ti_summary"]
    assert summary["eligible_file_sha256_count"] == 1
    assert summary["eligible_source_ip_count"] == 1
    assert summary["eligible_observable_count"] == 2
    assert summary["eligible_observable_counts"] == {"hash": 1, "ip": 1}
    assert response["counts"]["eligible_file_sha256"] == 1
    assert response["counts"]["eligible_source_ip"] == 1
    # The existing session contract remains source-IP-value safe.
    assert SOURCE_IP not in json.dumps(response)


def test_source_ip_gate_reads_policy_metadata_from_persisted_payload(tmp_path: Path) -> None:
    config = _source_config(tmp_path)
    sighting = _sighting("payload-provenance-session")
    # Mongo's bounded observable-sighting row stores role/source in payload;
    # this is the shape consumed by the enrichment worker after a read-back.
    sighting.pop("role")
    sighting.pop("source")
    governance = load_source_ip_governance_amendment(
        config.source_ip_governance_path,
        expected_sha256=config.source_ip_governance_sha256,
    )

    decision = evaluate_outbound_sighting(
        sighting,
        provider="abuseipdb",
        source_ip_governance=governance,
        source_ip_cutoff_utc=parse_source_ip_cutoff_utc(
            config.source_ip_enrichment_not_before_utc
        ),
        source_ip_mode=config.source_ip_enrichment_mode,
    )

    assert decision.eligible is True
    assert decision.code == "eligible_source_ip"
    assert decision.role == "source_ip"
    assert decision.source == "cowrie_event"


def test_source_ip_pivot_is_exact_role_scoped_bounded_and_excludes_session(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    for index, session_id in enumerate(("session-a", "session-b", "session-c")):
        storage.save_session({"session_id": session_id, "src_ip": SOURCE_IP})
        storage.record_observable_sighting(
            _sighting(
                session_id,
                timestamp=f"2026-09-05T09:0{index}:00Z",
            )
        )
        # Equal IP as a destination must not participate in the source-IP join.
        storage.record_observable_sighting(
            _sighting(
                session_id,
                role="destination_ip",
                sighting_id=f"{session_id}-destination",
            )
        )

    result = build_source_ip_cross_session_projection(
        storage,
        "8.8.8.8",
        exclude_session_id="session-a",
        limit=1,
    )
    assert result["ok"] is True
    assert result["schema_version"] == SOURCE_IP_CROSS_SESSION_SCHEMA
    assert result["observable"]["value"] == SOURCE_IP
    assert result["relationship"] == "EXACT_NORMALIZED_SOURCE_IP_OBSERVATION"
    assert [item["session_id"] for item in result["sessions"]] == ["session-c"]
    assert result["sessions"][0]["sighting_count"] == 1
    assert result["sessions"][0]["roles"] == ["source_ip"]
    assert result["provider_calls"] is False
    assert result["authority"] == "NON_AUTHORITATIVE_CONTEXT_ONLY"
    assert "8.8.8" not in json.dumps(result["sessions"])

    for malformed in ("8.8.8", "8.8.8.0/24", "not-an-ip"):
        invalid = build_source_ip_cross_session_projection(storage, malformed)
        assert invalid["ok"] is False
        assert invalid["error_code"] == "invalid_observable"


def test_source_ip_pivot_does_not_claim_unknown_session_completeness(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    for session_id in ("completeness-a", "completeness-b"):
        storage.save_session({"session_id": session_id, "src_ip": SOURCE_IP})
        storage.record_observable_sighting(
            _sighting(session_id, sighting_id=f"{session_id}-source-ip")
        )

    result = build_source_ip_cross_session_projection(
        storage,
        SOURCE_IP,
        limit=1,
    )

    assert result["completeness"]["sessions"] == "UNKNOWN"
    assert result["completeness"]["sessions_total"] is None
    assert result["completeness"]["sessions_truncated"] is None
    assert result["counts"]["sessions_total"] is None
    assert result["truncation"]["sessions"] is None


def test_observable_lookup_supports_sha256_and_rejects_unlisted_types(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    storage.save_session({"session_id": "hash-session", "src_ip": "192.0.2.4"})
    storage.record_observable_sighting(
        _sighting(
            "hash-session",
            observable_type="hash",
            observable_value=SHA256,
            role="file_hash",
            sighting_id="hash-sighting",
        )
    )
    payload, statuses, expires = merge_provider_results(
        "hash",
        SHA256,
        [ProviderResult("virustotal", "not_found", ttl_seconds=3600)],
        default_ttl_seconds=3600,
    )
    storage.save_enrichment_record("hash", SHA256, payload, statuses, expires)

    result = build_observable_ti_projection(storage, "sha256", SHA256)
    assert result["ok"] is True
    assert result["schema_version"] == OBSERVABLE_TI_SCHEMA
    assert result["observable"]["type"] == "hash"
    assert result["observable"]["value"] == SHA256
    assert result["evidence"][0]["lookup_status"] == "NOT_FOUND"
    assert result["evidence"][0]["scope"] == "observable"
    assert result["provider_calls"] is False
    assert all("payload" not in item for item in result["sightings"])

    unsupported = build_observable_ti_projection(storage, "domain", "example.invalid")
    assert unsupported["ok"] is False
    assert unsupported["error_code"] == "unsupported_observable_type"
    weak_hash = build_observable_ti_projection(storage, "hash", "b" * 40)
    assert weak_hash["ok"] is False
    assert weak_hash["error_code"] == "invalid_observable"


def test_monitor_read_models_use_stored_data_without_provider_calls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    storage = _storage(tmp_path)
    storage.save_session({"session_id": "api-session", "src_ip": SOURCE_IP})
    storage.record_observable_sighting(_sighting("api-session"))
    config = MonitorConfig(
        db_path=str(tmp_path / "state.db"),
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        reports_dir=str(tmp_path / "reports"),
    )

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("provider/network call from read model")

    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    pivot = load_source_ip_pivot(config, SOURCE_IP, _storage=storage)
    lookup = load_observable_ti(config, "ip", SOURCE_IP, _storage=storage)
    assert pivot["ok"] is True
    assert lookup["ok"] is True
    assert pivot["provider_calls"] is False
    assert lookup["provider_calls"] is False
    assert pivot["read_only"] is True
    assert lookup["read_only"] is True


def test_session_projection_explains_no_eligible_observable(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    storage.save_session({"session_id": "no-observable-session", "src_ip": "192.0.2.10"})

    result = build_session_ti_projection(
        storage,
        "no-observable-session",
        config=_source_config(tmp_path),
    )

    assert result["status"] == "TI_PENDING"
    assert result["status_reason"] == "NO_ELIGIBLE_OBSERVABLE"
    assert result["external_ti_summary"]["status_reason"] == "NO_ELIGIBLE_OBSERVABLE"
    assert result["counts"]["eligible_observables"] == 0


def test_source_ip_projection_does_not_promote_legacy_canonical_ip_context(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    session_id = "policy-blocked-session"
    storage.save_session({"session_id": session_id, "src_ip": SOURCE_IP})
    storage.record_observable_sighting(_sighting(session_id))
    payload, statuses, expires = merge_provider_results(
        "ip",
        SOURCE_IP,
        [ProviderResult("abuseipdb", "disabled")],
        default_ttl_seconds=3600,
    )
    storage.save_enrichment_record("ip", SOURCE_IP, payload, statuses, expires)

    result = build_session_ti_projection(
        storage,
        session_id,
        config=_source_config(tmp_path),
    )

    assert result["status"] == "TI_PENDING"
    assert result["status_reason"] == "NO_STORED_PROVIDER_RESULT"
    assert result["status_reason_text"]
    assert result["freshness"]["state"] == "TI_PENDING"


def test_source_ip_projection_ignores_expired_legacy_canonical_ip_context(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    session_id = "expired-policy-context-session"
    storage.save_session({"session_id": session_id, "src_ip": SOURCE_IP})
    storage.record_observable_sighting(_sighting(session_id))
    payload, statuses, _expires = merge_provider_results(
        "ip",
        SOURCE_IP,
        [ProviderResult("abuseipdb", "disabled")],
        default_ttl_seconds=3600,
    )
    storage.save_enrichment_record(
        "ip",
        SOURCE_IP,
        payload,
        statuses,
        expires_at="2000-01-01T00:00:00+00:00",
    )

    result = build_session_ti_projection(
        storage,
        session_id,
        config=_source_config(tmp_path),
    )

    assert result["status"] == "TI_PENDING"
    assert result["status_reason"] == "NO_STORED_PROVIDER_RESULT"
    assert result["status_reason_text"]
    assert result["freshness"]["state"] == "TI_PENDING"


def test_source_ip_observable_lookup_uses_governed_cache_provenance(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    storage.save_session({"session_id": "cache-session", "src_ip": SOURCE_IP})
    storage.record_observable_sighting(
        _sighting(
            "cache-session",
            sighting_id="cache-sighting",
            timestamp="2026-09-05T09:00:01Z",
        )
    )
    config = _source_config(tmp_path)
    SourceIPCacheService(storage).store_result(
        "abuseipdb",
        SOURCE_IP,
        ProviderResult("abuseipdb", "not_found"),
        config.external_ti_provider_configs["abuseipdb"],
    )

    result = build_observable_ti_projection(storage, "ip", SOURCE_IP, config=config)
    assert result["status"] == "TI_AVAILABLE"
    assert result["source_ip_cache"][0]["provider"] == "abuseipdb"
    assert result["source_ip_cache"][0]["provenance"]["cache_authority"] == "NON_AUTHORITATIVE_CACHE"
    assert result["source_ip_cache"][0]["provenance"]["provider_config_identity"]


def test_reviewed_2_3_cache_remains_readable_as_legacy_context_under_2_4(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    session_id = "reviewed-legacy-cache-session"
    storage.save_session({"session_id": session_id, "src_ip": SOURCE_IP})
    storage.record_observable_sighting(_sighting(session_id))
    policy_path = Path(__file__).resolve().parents[1] / "configs" / "external_ti_source_ip_governance.v2.json"
    config = replace(
        _source_config(tmp_path),
        source_ip_governance_path=str(policy_path),
        source_ip_governance_sha256=hashlib.sha256(policy_path.read_bytes()).hexdigest(),
    )
    entry = SourceIPCacheService(storage).store_result(
        "abuseipdb",
        SOURCE_IP,
        ProviderResult("abuseipdb", "ok", {"data": {"abuseConfidenceScore": 23, "totalReports": 4}}),
        config.external_ti_provider_configs["abuseipdb"],
        privacy_policy_version=SOURCE_IP_PRODUCTION_POLICY_V2_3_VERSION,
    )
    assert entry is not None
    result = build_session_ti_projection(storage, session_id, config=config)
    assert result["status"] == "TI_AVAILABLE"
    assert len(result["source_ip_cache"]) == 1
    assert result["source_ip_cache"][0]["policy_binding"] == "LEGACY_NON_AUTHORITATIVE_CONTEXT_ONLY"
    assert result["source_ip_cache"][0]["provenance"]["privacy_policy_version"] == SOURCE_IP_PRODUCTION_POLICY_V2_3_VERSION
    assert SOURCE_IP not in json.dumps(result)

    entry["provenance"]["privacy_policy_version"] = "unreviewed-version"
    storage.upsert_external_ti_source_ip_cache(entry)
    rejected = build_session_ti_projection(storage, session_id, config=config)
    assert rejected["source_ip_cache"] == []
    assert rejected["status"] == "TI_PENDING"

    entry["provenance"]["privacy_policy_version"] = SOURCE_IP_PRODUCTION_POLICY_V2_4_VERSION
    storage.upsert_external_ti_source_ip_cache(entry)
    current = build_session_ti_projection(storage, session_id, config=config)
    assert current["source_ip_cache"][0]["policy_binding"] == "CURRENT_POLICY"
