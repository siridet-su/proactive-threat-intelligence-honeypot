from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from production.enrichment.enrichment_providers import EnrichmentProvider, ProviderResult
from production.enrichment.local_snapshot import load_local_enrichment_snapshot
from production.utils.config import ProductionConfig
from production.utils.sensitive_data import (
    REDACTION_MARKER,
    sanitize_cowrie_event_for_persistence,
)
from production.utils.serialization import stable_json
from production.workers.enrichment_worker import EnrichmentWorker
from production.workers.sensor_forwarder import DiskSpool


def test_cowrie_credentials_are_removed_before_spool_and_sanitizer_is_idempotent(
    tmp_path,
) -> None:
    event = {
        "eventid": "cowrie.login.success",
        "session": "privacy-1",
        "username": "root",
        "password": "plaintext-secret",
        "nested": {"passwd": "second-secret", "safe": "value"},
    }
    sanitized = sanitize_cowrie_event_for_persistence(event)
    assert sanitized["username"] == REDACTION_MARKER
    assert sanitized["password"] == REDACTION_MARKER
    assert sanitized["nested"]["passwd"] == REDACTION_MARKER
    assert sanitized["nested"]["safe"] == "value"
    assert sanitized["_honeypot_privacy"] == {
        "schema_version": "cowrie_credential_sanitizer.v1",
        "credential_plaintext_removed": True,
        "credential_fields_redacted": ["passwd", "password", "username"],
    }
    assert sanitize_cowrie_event_for_persistence(sanitized) == sanitized

    spool = DiskSpool(str(tmp_path / "spool.ndjson"))
    assert spool.append_many([event], max_spool_bytes=4096, min_free_bytes=0) == 1
    persisted = (tmp_path / "spool.ndjson").read_text(encoding="utf-8")
    assert "plaintext-secret" not in persisted
    assert "second-secret" not in persisted
    assert json.loads(persisted)["password"] == REDACTION_MARKER


def _snapshot_document(records: dict, *, expired: bool = False) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "local_enrichment_snapshot.v1",
        "dataset_id": "operator-reviewed-fixture",
        "version": "2026-07-29",
        "generated_at": (now - timedelta(days=2)).isoformat(),
        "expires_at": (
            now - timedelta(days=1) if expired else now + timedelta(days=1)
        ).isoformat(),
        "records_sha256": hashlib.sha256(
            stable_json(records).encode("utf-8")
        ).hexdigest(),
        "records": records,
    }


def test_local_enrichment_snapshot_is_bounded_hashed_and_expiring(tmp_path) -> None:
    records = {"203.0.113.9": {"country": "ZZ", "asn": "AS64500"}}
    path = tmp_path / "local-enrichment.json"
    path.write_text(
        json.dumps(_snapshot_document(records), sort_keys=True),
        encoding="utf-8",
    )
    loaded = load_local_enrichment_snapshot(
        str(path),
        max_bytes=4096,
        max_records=2,
        allow_stale=False,
    )
    provenance = loaded["203.0.113.9"]["_local_snapshot"]
    assert provenance["records_sha256"] == hashlib.sha256(
        stable_json(records).encode("utf-8")
    ).hexdigest()
    assert provenance["authority"] == "non_authoritative_context_only"

    tampered = _snapshot_document(records)
    tampered["records_sha256"] = "0" * 64
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_local_enrichment_snapshot(
            str(path),
            max_bytes=4096,
            max_records=2,
            allow_stale=False,
        )

    path.write_text(
        json.dumps(_snapshot_document(records, expired=True)),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="expired"):
        load_local_enrichment_snapshot(
            str(path),
            max_bytes=4096,
            max_records=2,
            allow_stale=False,
        )


class _ExternalProbe(EnrichmentProvider):
    name = "probe"
    supported_types = {"ip", "domain"}
    external = True

    def __init__(self) -> None:
        self.calls = []

    def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
        self.calls.append((observable_type, observable_value))
        return ProviderResult(self.name, "ok", {"seen": True})


def test_external_enrichment_profile_never_shares_source_ip(tmp_path) -> None:
    probe = _ExternalProbe()
    config = ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        external_enrichment_profile="non_ip_observables",
    )
    worker = EnrichmentWorker(config, providers=[probe])

    blocked = worker._run_providers("ip", "203.0.113.9")
    assert probe.calls == []
    assert blocked[0].status == "policy_prohibited"

    allowed = worker._run_providers("domain", "example.invalid")
    assert probe.calls == [("domain", "example.invalid")]
    assert allowed[0].status == "ok"


def test_config_rejects_unknown_file_keys_and_invalid_boolean(tmp_path, monkeypatch) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"unknown_phase7_key": True}), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown keys"):
        ProductionConfig.from_env(str(path))

    path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("ENABLE_ENRICHMENT_JOBS", "sometimes")
    with pytest.raises(ValueError, match="ENABLE_ENRICHMENT_JOBS"):
        ProductionConfig.from_env(str(path))


def test_enrichment_context_fails_closed_on_stale_records_by_default() -> None:
    assert ProductionConfig().enrichment_allow_stale is False
