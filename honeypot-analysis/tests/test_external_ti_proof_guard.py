"""Offline proof of the durable source-IP at-most-once guard."""

from __future__ import annotations

import concurrent.futures
from pathlib import Path

import pytest

from production.enrichment.external_ti_proof_guard import (
    ExternalTIProofGuard,
    PROOF_GUARD_COLLECTION,
    PROOF_GUARD_MODE_PRE_FLIGHT,
    PROOF_GUARD_MODE_REAL,
    build_provider_claim,
    build_target_claim,
    source_ip_digest,
)
from production.enrichment.enrichment_providers import EnrichmentProvider, ProviderResult
from production.enrichment.external_ti_contract import (
    SOURCE_IP_AMENDMENT_SHA256,
    SOURCE_IP_ENRICHMENT_MODE,
    default_external_ti_provider_configs,
)
from production.storage.backend import SQLiteStorage, StorageError
from production.utils.config import ProductionConfig
from production.workers.enrichment_worker import EnrichmentWorker


CAMPAIGN = "eti-guard-offline-test"
CUTOFF = "2026-09-06T00:00:00Z"
OBSERVED = "2026-09-06T00:00:01Z"
IP = "8.8.8.8"


def _storage(tmp_path: Path) -> SQLiteStorage:
    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'guard.db'}")
    storage.initialize()
    return storage


def _guard(storage: SQLiteStorage, mode: str = PROOF_GUARD_MODE_REAL) -> ExternalTIProofGuard:
    return ExternalTIProofGuard(storage, CAMPAIGN, mode)


def test_first_claim_wins_across_instances_and_restart(tmp_path: Path) -> None:
    first = _guard(_storage(tmp_path))
    claimed = first.claim_for_provider(
        "abuseipdb", IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    )
    assert claimed.allowed
    assert claimed.code == "CLAIMED"

    same_process = _guard(_storage(tmp_path)).claim_for_provider(
        "abuseipdb", IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    )
    assert not same_process.allowed
    assert same_process.code == "REQUEST_CLAIMED_OUTCOME_UNKNOWN"

    restarted = _guard(_storage(tmp_path)).claim_for_provider(
        "abuseipdb", IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    )
    assert not restarted.allowed
    assert restarted.code == "REQUEST_CLAIMED_OUTCOME_UNKNOWN"


def test_provider_claims_are_distinct_and_completion_is_consumed(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    guard = _guard(storage)
    abuse = guard.claim_for_provider(
        "abuseipdb", IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    )
    shodan = guard.claim_for_provider(
        "shodan_official", IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    )
    assert abuse.allowed and shodan.allowed
    assert abuse.claim_id != shodan.claim_id
    assert guard.complete_provider("abuseipdb", "NO_DATA", http_status=200)
    assert not guard.claim_for_provider(
        "abuseipdb", IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    ).allowed
    rows = storage.list_external_ti_proof_guard(CAMPAIGN)
    assert len(rows) == 3
    assert {row["claim_type"] for row in rows} == {"target", "provider"}
    assert all("normalized_source_ip" not in row for row in rows)
    assert all(row["normalized_source_ip_digest"] == source_ip_digest(IP) for row in rows)


def test_otx_source_ip_claim_is_authorized_by_policy_v22(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    guard = _guard(storage)
    decision = guard.claim_for_provider(
        "otx", IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    )
    assert decision.allowed
    assert decision.code == "CLAIMED"
    assert decision.provider == "otx"


def test_different_ip_cannot_replace_frozen_target(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    guard = _guard(storage)
    assert guard.claim_for_provider(
        "abuseipdb", IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    ).allowed
    decision = guard.claim_for_provider(
        "shodan_official", "1.1.1.1", cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    )
    assert not decision.allowed
    assert decision.code == "TARGET_MISMATCH"
    assert len(storage.list_external_ti_proof_guard(CAMPAIGN)) == 2


def test_concurrent_same_provider_claim_has_one_winner(tmp_path: Path) -> None:
    storage = _storage(tmp_path)

    def claim(_: int):
        return _guard(storage).claim_for_provider(
            "shodan_official", IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(claim, range(16)))
    assert sum(result.allowed for result in results) == 1
    assert len(storage.list_external_ti_proof_guard(CAMPAIGN)) == 2


def test_storage_failure_denies_without_authorization(tmp_path: Path) -> None:
    class BrokenStorage:
        def claim_external_ti_proof_target(self, _entry):
            raise RuntimeError("storage unavailable")

    decision = ExternalTIProofGuard(
        BrokenStorage(), CAMPAIGN, PROOF_GUARD_MODE_REAL
    ).claim_for_provider(
        "abuseipdb", IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    )
    assert not decision.allowed
    assert decision.code == "GUARD_STORAGE_UNAVAILABLE"


def test_malformed_state_fails_closed(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    entry = build_target_claim(
        CAMPAIGN,
        IP,
        cutoff_utc=CUTOFF,
        first_observed_at=OBSERVED,
        mode=PROOF_GUARD_MODE_REAL,
    )
    with storage.connection() as connection:
        connection.execute(
            """
            INSERT INTO external_ti_provider_proof_guard
            (guard_id, schema_version, authority, claim_type, proof_campaign_id,
             provider, state, mode, normalized_observable_type,
             normalized_source_ip_digest, cutoff_utc, target_guard_id,
             first_observed_at, claimed_at, completed_at, result_class,
             http_status, provenance_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry["guard_id"], entry["schema_version"], entry["authority"],
                entry["claim_type"], entry["proof_campaign_id"], entry["provider"],
                "CORRUPT", entry["mode"], entry["normalized_observable_type"],
                entry["normalized_source_ip_digest"], entry["cutoff_utc"],
                entry["target_guard_id"], entry["first_observed_at"],
                entry["claimed_at"], "", "", None,
                '{"cache_authority":"NON_AUTHORITATIVE_OPERATIONAL_SAFETY_STATE",'
                '"component":"external_ti_proof_guard",'
                '"schema_version":"external_ti_provider_proof_guard.v1",'
                '"source_ip_representation":"sha256_normalized_public_ip"}',
                entry["created_at"], entry["updated_at"],
            ),
        )
    decision = _guard(storage).claim_target(
        IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    )
    assert not decision.allowed
    assert decision.code == "GUARD_STORAGE_UNAVAILABLE"


def test_preflight_rows_are_persistent_and_no_ttl_index_exists(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    guard = _guard(storage, PROOF_GUARD_MODE_PRE_FLIGHT)
    assert guard.claim_for_provider(
        "abuseipdb", "9.9.9.9", cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    ).allowed
    indexes = storage.connection
    with indexes() as connection:
        index_rows = connection.execute(
            "PRAGMA index_list(external_ti_provider_proof_guard)"
        ).fetchall()
    assert not any(
        any(token in str(row[1]).lower() for token in ("ttl", "expire", "expiry"))
        for row in index_rows
    )
    assert len(storage.list_external_ti_proof_guard(CAMPAIGN)) == 2


def test_crash_before_claim_does_not_consume_provider_and_claim_survives_send_gap(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path)
    guard = _guard(storage)
    # No pre-claim is present, so the first post-restart claimant is allowed.
    first = guard.claim_for_provider(
        "abuseipdb", IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    )
    assert first.allowed
    # Model a process crash after the durable claim and before HTTP completion.
    restarted = _guard(_storage(tmp_path))
    assert not restarted.claim_for_provider(
        "abuseipdb", IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    ).allowed
    assert not restarted.claim_for_provider(
        "abuseipdb", IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    ).allowed


def test_provider_binding_rejects_wrong_target_digest(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    target = _guard(storage).claim_target(
        IP, cutoff_utc=CUTOFF, first_observed_at=OBSERVED
    )
    assert target.allowed
    entry = build_provider_claim(
        CAMPAIGN,
        "abuseipdb",
        normalized_source_ip="1.1.1.1",
        target_claim_id=target.claim_id,
        cutoff_utc=CUTOFF,
        first_observed_at=OBSERVED,
        mode=PROOF_GUARD_MODE_REAL,
    )
    with pytest.raises(StorageError):
        storage.claim_external_ti_proof_provider(entry)


def test_worker_claims_before_provider_call_and_denies_after_restart(tmp_path: Path) -> None:
    policy_path = Path(__file__).resolve().parents[1] / "configs" / "external_ti_source_ip_governance_amendment.v1.json"
    configs = default_external_ti_provider_configs()
    configs["abuseipdb"].update({"enabled": True, "minute_limit": 10, "daily_budget": 10})
    config = ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'worker.db'}",
        external_enrichment_profile="source_ip_observables",
        external_ti_enabled=True,
        external_ti_provider_allowlist=["abuseipdb"],
        external_ti_provider_configs=configs,
        source_ip_enrichment_mode=SOURCE_IP_ENRICHMENT_MODE,
        source_ip_enrichment_not_before_utc=CUTOFF,
        source_ip_enrichment_cutoff_operator="guard-worker-test",
        source_ip_governance_path=str(policy_path),
        source_ip_governance_sha256=SOURCE_IP_AMENDMENT_SHA256,
        external_ti_proof_campaign_id=CAMPAIGN,
        external_ti_proof_guard_mode=PROOF_GUARD_MODE_REAL,
    )

    class FakeProvider(EnrichmentProvider):
        external = True
        requires_credential = False
        name = "abuseipdb"
        supported_types = {"ip"}

        def __init__(self) -> None:
            self.calls = 0

        def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
            self.calls += 1
            return ProviderResult(
                self.name,
                "not_found",
                ttl_seconds=86400,
                endpoint_id="abuseipdb_check_v2",
                attempt_count=1,
            )

    first_provider = FakeProvider()
    first_worker = EnrichmentWorker(config, providers=[first_provider])
    sighting = {
        "observable_type": "ip",
        "observable_value": IP,
        "role": "source_ip",
        "source": "cowrie_event",
        "session_id": "guard-worker-session",
        "event_id": "guard-worker-event",
        "sensor_id": "guard-worker-sensor",
        "timestamp": OBSERVED,
        "payload": {
            "role": "source_ip",
            "source": "cowrie_event",
            "metadata": {"is_public": True},
        },
    }
    first = first_worker._run_providers("ip", IP, sighting=sighting)
    assert first_provider.calls == 1
    assert first[0].status == "not_found"

    second_provider = FakeProvider()
    second_worker = EnrichmentWorker(config, providers=[second_provider])
    second = second_worker._run_providers("ip", IP, sighting=sighting)
    assert second_provider.calls == 0
    denied = next(item for item in second if item.provider == "abuseipdb")
    assert denied.status == "policy_prohibited"
    assert denied.data == {"gate": "ALREADY_COMPLETED"}
