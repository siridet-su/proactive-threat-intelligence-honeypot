"""Offline checks for bounded continuous source-IP ETI activation."""

from __future__ import annotations

import hashlib
from pathlib import Path

from production.enrichment.external_ti_contract import (
    SOURCE_IP_PRODUCTION_POLICY_V2_4_SHA256,
    SOURCE_IP_PRODUCTION_POLICY_V2_4_VERSION,
    load_source_ip_governance_amendment,
)
from production.enrichment.external_ti_proof_guard import (
    ExternalTIProductionGuard,
    PROOF_GUARD_MODE_REAL,
    production_guard_campaigns,
)
from production.storage.backend import SQLiteStorage


POLICY_PATH = (
    Path(__file__).resolve().parents[1]
    / "configs"
    / "external_ti_source_ip_governance.v2.json"
)


def _storage(tmp_path: Path) -> SQLiteStorage:
    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'production-guard.db'}")
    storage.initialize()
    return storage


def test_production_policy_is_hash_bound_and_bounded() -> None:
    digest = hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest()
    assert digest == SOURCE_IP_PRODUCTION_POLICY_V2_4_SHA256
    policy = load_source_ip_governance_amendment(
        str(POLICY_PATH),
        expected_sha256=digest,
    )
    assert policy.version == SOURCE_IP_PRODUCTION_POLICY_V2_4_VERSION
    assert policy.continuous_processing is True
    assert policy.minimum_refresh_interval_seconds == 86_400
    assert policy.max_distinct_source_ips_per_utc_day == 200
    assert policy.canonical_mongodb_enrichment_record_write is False
    assert set(policy.authorized_providers) == {"abuseipdb", "otx", "shodan_official"}
    assert policy.allowed_outbound_fields == (
        "normalized_source_ip",
        "sha256_file_hash",
    )
    assert policy.authorizes_provider("shodan_official")
    assert policy.authorizes_provider("otx")
    assert not policy.authorizes_provider("shodan_internetdb")


def test_campaign_identities_do_not_contain_source_ip() -> None:
    quota, request = production_guard_campaigns(
        "production-eti-v2",
        "8.8.8.8",
        observed_at="2026-09-18T00:00:00Z",
        max_daily_targets=10,
    )
    assert "8.8.8.8" not in quota
    assert "8.8.8.8" not in request
    assert quota != request


def test_same_source_is_at_most_once_per_provider_and_day(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    guard = ExternalTIProductionGuard(
        storage,
        "production-eti-v2",
        PROOF_GUARD_MODE_REAL,
        max_daily_targets=10,
    )
    first = guard.claim_for_provider(
        "abuseipdb",
        "8.8.8.8",
        cutoff_utc="2026-09-18T00:00:00Z",
        first_observed_at="2026-09-18T01:00:00Z",
    )
    assert first.allowed
    assert guard.complete_provider("abuseipdb", "DATA", http_status=200)
    repeated = guard.claim_for_provider(
        "abuseipdb",
        "8.8.8.8",
        cutoff_utc="2026-09-18T00:00:00Z",
        first_observed_at="2026-09-18T02:00:00Z",
    )
    assert not repeated.allowed


def test_daily_quota_slot_collision_fails_closed_and_next_day_reopens(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path)
    guard = ExternalTIProductionGuard(
        storage,
        "production-eti-v2",
        PROOF_GUARD_MODE_REAL,
        max_daily_targets=1,
    )
    first = guard.claim_for_provider(
        "abuseipdb",
        "8.8.8.8",
        cutoff_utc="2026-09-18T00:00:00Z",
        first_observed_at="2026-09-18T01:00:00Z",
    )
    assert first.allowed
    assert guard.complete_provider("abuseipdb", "NO_DATA", http_status=200)
    blocked = guard.claim_for_provider(
        "abuseipdb",
        "1.1.1.1",
        cutoff_utc="2026-09-18T00:00:00Z",
        first_observed_at="2026-09-18T02:00:00Z",
    )
    assert not blocked.allowed
    assert blocked.code.startswith("DAILY_QUOTA_")

    next_day = guard.claim_for_provider(
        "abuseipdb",
        "1.1.1.1",
        cutoff_utc="2026-09-18T00:00:00Z",
        first_observed_at="2026-09-19T02:00:00Z",
    )
    assert next_day.allowed


def test_daily_quota_uses_all_slots_before_failing_closed(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    guard = ExternalTIProductionGuard(
        storage,
        "production-eti-v2",
        PROOF_GUARD_MODE_REAL,
        max_daily_targets=2,
    )
    first = guard.claim_for_provider(
        "abuseipdb",
        "8.8.8.8",
        cutoff_utc="2026-09-18T00:00:00Z",
        first_observed_at="2026-09-18T01:00:00Z",
    )
    assert first.allowed
    assert guard.complete_provider("abuseipdb", "DATA", http_status=200)

    second = guard.claim_for_provider(
        "abuseipdb",
        "1.1.1.1",
        cutoff_utc="2026-09-18T00:00:00Z",
        first_observed_at="2026-09-18T02:00:00Z",
    )
    assert second.allowed
    assert guard.complete_provider("abuseipdb", "NO_DATA", http_status=200)

    exhausted = guard.claim_for_provider(
        "abuseipdb",
        "9.9.9.9",
        cutoff_utc="2026-09-18T00:00:00Z",
        first_observed_at="2026-09-18T03:00:00Z",
    )
    assert not exhausted.allowed
    assert exhausted.code == "DAILY_QUOTA_EXHAUSTED"


def test_reviewed_200_target_increase_preserves_prior_daily_claims(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    original = ExternalTIProductionGuard(
        storage, "production-eti-v2", PROOF_GUARD_MODE_REAL,
        max_daily_targets=100,
    )
    for suffix in range(1, 101):
        decision = original.claim_for_provider(
            "abuseipdb", f"11.0.0.{suffix}",
            cutoff_utc="2026-09-18T00:00:00Z",
            first_observed_at="2026-09-18T01:00:00Z",
        )
        assert decision.allowed
        assert original.complete_provider("abuseipdb", "NO_DATA", http_status=200)

    revised = ExternalTIProductionGuard(
        storage, "production-eti-v2", PROOF_GUARD_MODE_REAL,
        max_daily_targets=200,
    )
    for suffix in range(101, 201):
        extra = revised.claim_for_provider(
            "abuseipdb", f"11.0.0.{suffix}",
            cutoff_utc="2026-09-18T00:00:00Z",
            first_observed_at="2026-09-18T02:00:00Z",
        )
        assert extra.allowed
        assert revised.complete_provider("abuseipdb", "NO_DATA", http_status=200)
    assert not revised.claim_for_provider(
        "abuseipdb", "11.0.0.201",
        cutoff_utc="2026-09-18T00:00:00Z",
        first_observed_at="2026-09-18T03:00:00Z",
    ).allowed


def test_guard_rows_never_store_plain_source_ip(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    guard = ExternalTIProductionGuard(
        storage,
        "production-eti-v2",
        PROOF_GUARD_MODE_REAL,
        max_daily_targets=10,
    )
    assert guard.claim_for_provider(
        "shodan_official",
        "8.8.4.4",
        cutoff_utc="2026-09-18T00:00:00Z",
        first_observed_at="2026-09-18T03:00:00Z",
    ).allowed
    rows = storage.list_external_ti_proof_guard(limit=100)
    assert rows
    assert all("8.8.4.4" not in str(row) for row in rows)
