from __future__ import annotations

import os
import time

import pytest

from production.storage import CanonicalEventRecord, MongoDBStorageBackend, install_mongodb_schema


def _record(label: str) -> CanonicalEventRecord:
    return CanonicalEventRecord.create(
        "sensor-failure",
        {"eventid": "cowrie.command.input", "session": "sensor-failure:session", "input": label},
        received_at="2026-08-12T00:00:00Z",
    )


def test_network_unavailable_fails_closed_without_fallback() -> None:
    storage = MongoDBStorageBackend(
        "mongodb://127.0.0.1:27999/?directConnection=true", timeout_ms=100
    )
    assert storage.health_check() == {"ok": False, "backend": "mongodb"}


@pytest.mark.skipif(
    os.getenv("MONGODB_AUTH_FAILURE_URI") is None,
    reason="isolated authenticated MongoDB failure URI is not configured",
)
def test_authentication_failure_is_reported_without_fallback() -> None:
    storage = MongoDBStorageBackend(os.environ["MONGODB_AUTH_FAILURE_URI"], timeout_ms=500)
    assert storage.health_check() == {"ok": False, "backend": "mongodb"}


@pytest.mark.skipif(
    os.getenv("MONGODB_FAILPOINTS") != "1",
    reason="isolated MongoDB failCommand support is not enabled",
)
def test_ambiguous_insert_disconnect_retries_to_one_exact_record() -> None:
    pymongo = pytest.importorskip("pymongo")
    uri = os.environ["MONGODB_TEST_URI"]
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5_000, retryWrites=True)
    client.drop_database("honeypot_canonical_v1"); install_mongodb_schema(client)
    storage = MongoDBStorageBackend(client=client); storage.initialize(); record = _record("ambiguous")
    client.admin.command({"configureFailPoint": "failCommand", "mode": {"times": 1}, "data": {"failCommands": ["insert"], "closeConnection": True}})
    try:
        assert storage.store_canonical_event(record) == (record.event_id, True)
        assert storage.store_canonical_event(record) == (record.event_id, False)
        assert storage.database.events.count_documents({"_id": record.event_id}) == 1
    finally:
        client.admin.command({"configureFailPoint": "failCommand", "mode": "off"})
        client.drop_database("honeypot_canonical_v1"); client.close()


@pytest.mark.skipif(
    os.getenv("MONGODB_FAILOVER_TEST") != "1",
    reason="isolated replica-set stepdown test is not enabled",
)
def test_primary_stepdown_recovers_without_identity_change() -> None:
    pymongo = pytest.importorskip("pymongo")
    uri = os.environ["MONGODB_TEST_URI"]
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5_000, retryWrites=True)
    client.drop_database("honeypot_canonical_v1"); install_mongodb_schema(client)
    storage = MongoDBStorageBackend(client=client); storage.initialize(); before = _record("before")
    storage.store_canonical_event(before)
    try:
        try:
            client.admin.command({"replSetStepDown": 2, "force": True})
        except pymongo.errors.AutoReconnect:
            pass
        assert storage.health_check()["ok"] is False
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not storage.health_check()["ok"]:
            time.sleep(0.2)
        assert storage.health_check()["ok"] is True
        after = _record("after")
        assert storage.store_canonical_event(after) == (after.event_id, True)
        assert storage.get_event(before.event_id)["payload_json"] == before.payload_json
    finally:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not storage.health_check()["ok"]:
            time.sleep(0.2)
        if storage.health_check()["ok"]:
            client.drop_database("honeypot_canonical_v1")
        client.close()
