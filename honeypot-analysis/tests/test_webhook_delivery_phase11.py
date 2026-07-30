from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from production.storage import open_storage
from production.utils.config import ProductionConfig
from production.utils.serialization import stable_json
from production.workers import webhook_dispatcher


T0 = "2026-07-19T00:00:00+00:00"
T1 = "2026-07-19T00:00:30+00:00"
T2 = "2026-07-19T00:01:01+00:00"


class FakeResponse:
    def __init__(self, status: int, body: bytes = b"") -> None:
        self.status = status
        self.body = body

    def read(self, amount: int = -1) -> bytes:
        return self.body if amount < 0 else self.body[:amount]

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def _key_file(tmp_path: Path, name: str = "webhook-key") -> Path:
    path = tmp_path / name
    path.write_bytes((f"fake-{name}-material-".encode("ascii") * 4)[:64])
    os.chmod(path, 0o600)
    return path


def _config(tmp_path: Path, **overrides: object) -> ProductionConfig:
    values: dict[str, object] = {
        "database_url": f"sqlite:///{tmp_path / 'state.db'}",
        "webhook_signing_key_file": str(_key_file(tmp_path)),
        "webhook_allowed_schemes": ["https"],
        "webhook_timeout_seconds": 5,
        "webhook_lease_seconds": 30,
        "webhook_retry_seconds": 10,
        "webhook_max_attempts": 3,
    }
    values.update(overrides)
    return ProductionConfig(**values)


def _alert(alert_id: str = "alert-phase11") -> dict:
    return {
        "alert_id": alert_id,
        "session_id": "session-phase11",
        "severity": "HIGH",
        "reason": "verified phase 11 alert",
    }


def test_post_webhook_signs_exact_body_and_bounds_response(tmp_path, monkeypatch) -> None:
    captured: dict[str, object] = {}
    response_secret = b"response-secret-that-must-not-be-stored"

    def open_request(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse(200, response_secret)

    monkeypatch.setattr(webhook_dispatcher, "_open_no_redirect", open_request)
    key = _key_file(tmp_path).read_bytes()
    payload = {
        "type": "alert",
        "timestamp": T0,
        "idempotency_key": "delivery_exact",
        "alert": {"severity": "HIGH"},
    }

    result = webhook_dispatcher.post_webhook(
        "https://hooks.example.test/alerts",
        payload,
        5,
        signing_key=key,
        timestamp=T0,
        idempotency_key="delivery_exact",
        max_response_bytes=8,
    )

    request = captured["request"]
    body = stable_json(payload).encode("utf-8")
    message = b"\n".join([b"v1", T0.encode(), b"delivery_exact", body])
    expected_signature = "v1=" + hmac.new(key, message, hashlib.sha256).hexdigest()
    assert request.data == body
    assert request.get_header("X-honeypot-timestamp") == T0
    assert request.get_header("X-honeypot-idempotency-key") == "delivery_exact"
    assert request.get_header("X-honeypot-signature") == expected_signature
    assert captured["timeout"] == 5
    assert result.delivered is True
    assert result.retryable is False
    assert result.response_status == 200
    assert result.response_body_bytes == 8
    assert result.response_body_truncated is True
    assert result.response_body_sha256 == hashlib.sha256(response_secret[:8]).hexdigest()
    assert "response-secret" not in json.dumps(result.__dict__)


@pytest.mark.parametrize(
    ("status", "delivered", "retryable"),
    [(204, True, False), (302, False, False), (400, False, False), (408, False, True),
     (425, False, True), (429, False, True), (500, False, True), (503, False, True)],
)
def test_http_retry_classification_is_explicit(status, delivered, retryable) -> None:
    result = webhook_dispatcher._http_result(status, FakeResponse(status), 16)
    assert result.delivered is delivered
    assert result.retryable is retryable
    assert result.response_status == status


def test_redirect_handler_refuses_redirects() -> None:
    assert (
        webhook_dispatcher._NoRedirectHandler().redirect_request(
            None, None, 302, "Found", {}, "http://127.0.0.1/internal"
        )
        is None
    )


def test_endpoint_policy_rejects_scheme_credentials_fragment_and_internal_dns(
    monkeypatch,
) -> None:
    with pytest.raises(webhook_dispatcher.WebhookConfigurationError, match="scheme"):
        webhook_dispatcher._normalize_endpoint("ftp://example.com/hook", ["https"])
    with pytest.raises(webhook_dispatcher.WebhookConfigurationError, match="user"):
        webhook_dispatcher._normalize_endpoint(
            "https://user:password@example.com/hook", ["https"]
        )
    with pytest.raises(webhook_dispatcher.WebhookConfigurationError, match="fragment"):
        webhook_dispatcher._normalize_endpoint(
            "https://example.com/hook#fragment", ["https"]
        )

    monkeypatch.setattr(
        webhook_dispatcher.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (webhook_dispatcher.socket.AF_INET, 1, 6, "", ("127.0.0.1", 443))
        ],
    )
    with pytest.raises(webhook_dispatcher.WebhookEndpointError) as failure:
        webhook_dispatcher.validate_resolved_endpoint(
            "https://hooks.example.test/", allow_private_networks=False
        )
    assert failure.value.code == "webhook_endpoint_internal"
    assert failure.value.retryable is False
    webhook_dispatcher.validate_resolved_endpoint(
        "https://hooks.example.test/", allow_private_networks=True
    )


def test_dns_failure_is_retryable_without_rendering_hostname(monkeypatch) -> None:
    def fail_dns(*_args, **_kwargs):
        raise OSError("secret-hostname-material")

    monkeypatch.setattr(webhook_dispatcher.socket, "getaddrinfo", fail_dns)
    with pytest.raises(webhook_dispatcher.WebhookEndpointError) as failure:
        webhook_dispatcher.validate_resolved_endpoint(
            "https://secret-hostname.example.test/hook",
            allow_private_networks=False,
        )
    assert failure.value.code == "webhook_dns_unavailable"
    assert str(failure.value) == "webhook_dns_unavailable"
    assert failure.value.retryable is True


def test_dns_resolution_deadline_is_bounded_even_if_resolver_never_returns(
    monkeypatch,
) -> None:
    release = threading.Event()

    def never_returns(*_args, **_kwargs):
        release.wait(1)
        return []

    monkeypatch.setattr(webhook_dispatcher.socket, "getaddrinfo", never_returns)
    started = time.monotonic()
    try:
        with pytest.raises(webhook_dispatcher.WebhookEndpointError) as failure:
            webhook_dispatcher.validate_resolved_endpoint(
                "https://hooks.example.test/hook",
                allow_private_networks=False,
                dns_timeout_seconds=0.01,
            )
    finally:
        release.set()
    assert time.monotonic() - started < 0.25
    assert failure.value.code == "webhook_dns_unavailable"
    assert failure.value.retryable is True


def test_disabled_default_does_not_require_or_read_a_signing_key(tmp_path) -> None:
    config = ProductionConfig(database_url=f"sqlite:///{tmp_path / 'state.db'}")
    dispatcher = webhook_dispatcher.WebhookDispatcher(config)
    assert dispatcher.targets == []
    assert dispatcher.dispatch_once() == 0


def test_enabled_target_requires_private_bounded_regular_key(tmp_path) -> None:
    missing = _config(tmp_path, webhook_signing_key_file=str(tmp_path / "missing"))
    missing.webhook_url = "https://hooks.example.test/"
    with pytest.raises(webhook_dispatcher.WebhookConfigurationError, match="cannot be opened"):
        webhook_dispatcher.WebhookDispatcher(missing)

    broad_path = _key_file(tmp_path, "broad-key")
    os.chmod(broad_path, 0o644)
    broad = _config(tmp_path, webhook_signing_key_file=str(broad_path))
    broad.webhook_url = "https://hooks.example.test/"
    with pytest.raises(webhook_dispatcher.WebhookConfigurationError, match="permissions"):
        webhook_dispatcher.WebhookDispatcher(broad)


def test_sqlite_per_target_claims_are_leased_and_crash_recoverable(tmp_path) -> None:
    config = _config(tmp_path)
    storage = open_storage(config.database_url)
    alert_id = storage.store_alert(_alert())
    target_a = webhook_dispatcher.target_hash("https://a.example.test/hook")
    target_b = webhook_dispatcher.target_hash("https://b.example.test/hook")
    assert [row["alert_id"] for row in storage.pending_webhooks(
        target_url_hash=target_a, max_attempts=3, now=T0
    )] == [alert_id]

    payload = {"type": "alert", "alert": _alert(), "idempotency_key": "stable"}
    first = storage.claim_webhook_delivery(
        payload, target_a, "worker-a", 60, 3, alert_id=alert_id, now=T0
    )
    assert first is not None
    assert first["attempts"] == 1
    assert storage.claim_webhook_delivery(
        payload, target_a, "worker-b", 60, 3, alert_id=alert_id, now=T1
    ) is None
    assert [row["alert_id"] for row in storage.pending_webhooks(
        target_url_hash=target_b, max_attempts=3, now=T1
    )] == [alert_id]

    recovered = storage.claim_webhook_delivery(
        payload, target_a, "worker-b", 60, 3, alert_id=alert_id, now=T2
    )
    assert recovered is not None
    assert recovered["delivery_id"] == first["delivery_id"]
    assert recovered["attempts"] == 2
    assert storage.complete_webhook_delivery(
        first["delivery_id"],
        "worker-a",
        first["claim_token"],
        "delivered",
        now=T2,
    ) is False
    assert storage.complete_webhook_delivery(
        recovered["delivery_id"],
        "worker-b",
        recovered["claim_token"],
        "delivered",
        response_status=204,
        now=T2,
    ) is True
    assert storage.pending_webhooks(
        target_url_hash=target_a, max_attempts=3, now=T2
    ) == []


def test_sqlite_legacy_webhook_table_is_migrated_in_place(tmp_path) -> None:
    database_path = tmp_path / "legacy.db"
    connection = sqlite3.connect(database_path)
    connection.execute(
        """
        CREATE TABLE webhook_deliveries (
            delivery_id TEXT PRIMARY KEY,
            alert_id TEXT,
            report_id TEXT,
            target_url_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.commit()
    connection.close()

    storage = open_storage(f"sqlite:///{database_path}")
    with storage.connection() as migrated:
        columns = {
            row["name"] for row in migrated.execute(
                "PRAGMA table_info(webhook_deliveries)"
            ).fetchall()
        }
        indexes = {
            row["name"] for row in migrated.execute(
                "PRAGMA index_list(webhook_deliveries)"
            ).fetchall()
        }

    assert {
        "error_code",
        "next_retry_at",
        "claim_owner",
        "claim_token",
        "claim_expires_at",
        "response_status",
        "response_body_sha256",
        "response_body_bytes",
        "response_body_truncated",
        "completed_at",
    } <= columns
    assert "idx_webhook_target_claimable" in indexes


def test_crash_on_final_attempt_transitions_to_terminal_state(tmp_path) -> None:
    config = _config(tmp_path)
    storage = open_storage(config.database_url)
    alert_id = storage.store_alert(_alert("alert-final-crash"))
    target = webhook_dispatcher.target_hash("https://a.example.test/hook")
    claim = storage.claim_webhook_delivery(
        {"alert": _alert("alert-final-crash")},
        target,
        "worker-a",
        60,
        1,
        alert_id=alert_id,
        now=T0,
    )
    assert claim is not None
    assert storage.pending_webhooks(
        target_url_hash=target, max_attempts=1, now=T2
    )
    assert storage.claim_webhook_delivery(
        {"alert": _alert("alert-final-crash")},
        target,
        "worker-b",
        60,
        1,
        alert_id=alert_id,
        now=T2,
    ) is None
    delivery = storage.get_webhook_delivery(claim["delivery_id"])
    assert delivery["status"] == "permanent_failure"
    assert delivery["error_code"] == "webhook_lease_attempts_exhausted"


def test_completion_registry_blocks_secret_shaped_failure_metadata(tmp_path) -> None:
    config = _config(tmp_path)
    storage = open_storage(config.database_url)
    alert_id = storage.store_alert(_alert("alert-safe-failure"))
    target = webhook_dispatcher.target_hash("https://a.example.test/hook")
    claim = storage.claim_webhook_delivery(
        {"alert": _alert("alert-safe-failure")},
        target,
        "worker-a",
        60,
        3,
        alert_id=alert_id,
        now=T0,
    )
    assert claim is not None
    with pytest.raises(ValueError, match="registered webhook failure code"):
        storage.complete_webhook_delivery(
            claim["delivery_id"],
            "worker-a",
            claim["claim_token"],
            "permanent_failure",
            error_code="attacker-secret-code",
            error="attacker-secret-value",
            now=T0,
        )
    assert storage.complete_webhook_delivery(
        claim["delivery_id"],
        "worker-a",
        claim["claim_token"],
        "permanent_failure",
        error_code="webhook_endpoint_internal",
        error="attacker-secret-value",
        now=T0,
    ) is True
    stored = storage.get_webhook_delivery(claim["delivery_id"])
    assert stored["error_code"] == "webhook_endpoint_internal"
    assert stored["last_error"] == "operation_failed"
    assert "attacker-secret" not in json.dumps(stored)


def test_two_sqlite_dispatchers_cannot_claim_same_logical_delivery(tmp_path) -> None:
    config = _config(tmp_path)
    storage = open_storage(config.database_url)
    alert_id = storage.store_alert(_alert("alert-concurrent-claim"))
    target = webhook_dispatcher.target_hash("https://a.example.test/hook")

    def claim(owner: str):
        independent = open_storage(config.database_url)
        return independent.claim_webhook_delivery(
            {"alert": _alert("alert-concurrent-claim")},
            target,
            owner,
            60,
            3,
            alert_id=alert_id,
            now=T0,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(claim, ["worker-a", "worker-b"]))

    assert sum(result is not None for result in results) == 1
    delivery = storage.get_webhook_delivery(
        webhook_dispatcher.webhook_delivery_id(
            alert_id=alert_id, target_url_hash=target
        )
    )
    assert delivery["attempts"] == 1
    assert delivery["status"] == "in_progress"


def test_dispatcher_validates_but_does_not_deliver_configured_targets_without_authority(
    tmp_path, monkeypatch
) -> None:
    key_a = _key_file(tmp_path, "key-a")
    key_b = _key_file(tmp_path, "key-b")
    config = _config(
        tmp_path,
        webhook_targets=[
            {
                "target_id": "a",
                "url": "https://a.example.test/hook",
                "signing_key_file": str(key_a),
            },
            {
                "target_id": "b",
                "url": "https://b.example.test/hook",
                "signing_key_file": str(key_b),
            },
        ],
    )
    storage = open_storage(config.database_url)
    raw = _alert("alert-two-targets")
    raw["password"] = "attacker-secret-password"
    alert_id = storage.store_alert(raw)
    captured_payloads: list[dict] = []

    monkeypatch.setattr(
        webhook_dispatcher,
        "validate_resolved_endpoint",
        lambda *_args, **_kwargs: None,
    )

    def fake_post(url, payload, *_args, **_kwargs):
        captured_payloads.append(payload)
        if url.startswith("https://a."):
            return webhook_dispatcher.WebhookPostResult(
                True,
                False,
                response_status=204,
                response_body_sha256=hashlib.sha256(b"bounded").hexdigest(),
                response_body_bytes=7,
                response_body_truncated=True,
            )
        return webhook_dispatcher.WebhookPostResult(
            False,
            True,
            error_code="webhook_http_503",
            error="HTTP 503",
            response_status=503,
        )

    monkeypatch.setattr(webhook_dispatcher, "post_webhook", fake_post)
    dispatcher = webhook_dispatcher.WebhookDispatcher(
        config, storage=storage, worker_id="webhook-test-worker"
    )

    assert len(dispatcher.configured_targets) == 2
    assert dispatcher.targets == []
    assert dispatcher.dispatch_once() == 0
    assert captured_payloads == []
    assert storage.list_rows("webhook_deliveries") == []
    # Historical rows stay readable, but the reviewed policy cannot deliver them.
    assert storage.list_rows("alerts", limit=1)[0]["delivered"] == 0


def test_webhook_configuration_bounds_and_lease_relationship() -> None:
    with pytest.raises(ValueError, match="combined DNS and request"):
        ProductionConfig(webhook_timeout_seconds=30, webhook_lease_seconds=30)
    with pytest.raises(ValueError, match="between 0 and 65536"):
        ProductionConfig(webhook_max_response_bytes=65537)
    with pytest.raises(ValueError, match="only http or https"):
        ProductionConfig(webhook_allowed_schemes=["file"])
