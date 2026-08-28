from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from production.ai_advisory.contracts import AIAdvisoryContractError
from production.ai_advisory.http_transport import post_json
from production.ai_advisory.provider import AIProviderUnavailable
from production.ai_advisory.security import read_secure_file, validate_https_endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://api.example.test/v1/advisory",
        "https://user:secret@api.example.test/v1/advisory",
        "https://api.example.test:8443/v1/advisory",
        "https://api.example.test/v1/advisory?api_key=secret",
        "https://api.example.test/v1/advisory#fragment",
        "https://api.example.test/v1/%0d%0aadvisory",
        "https://api.example.test/v1/../advisory",
        "https://127.0.0.1/v1/advisory",
        "https://unexpected.example.test/v1/advisory",
    ],
)
def test_hosted_endpoint_validation_rejects_unsafe_forms(endpoint: str) -> None:
    with pytest.raises(ValueError):
        validate_https_endpoint(endpoint, ["api.example.test"])


class _Response:
    def __init__(
        self,
        status: int = 200,
        body: bytes = b'{"ok":true}',
        *,
        content_type: str = "application/json",
        content_encoding: str = "identity",
        content_length: str | None = None,
    ) -> None:
        self.status = status
        self.body = body
        self.headers = {
            "Content-Type": content_type,
            "Content-Encoding": content_encoding,
            "Content-Length": content_length if content_length is not None else str(len(body)),
        }

    def getheader(self, name: str):
        return self.headers.get(name)

    def read(self, amount: int = -1) -> bytes:
        return self.body if amount < 0 else self.body[:amount]


class _Connection:
    response = _Response()
    instances: list["_Connection"] = []

    def __init__(self, host, port, *, timeout, context):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.request_call = None
        self.closed = False
        self.__class__.instances.append(self)

    def request(self, method, target, *, body, headers):
        self.request_call = (method, target, body, headers)

    def getresponse(self):
        return self.__class__.response

    def close(self):
        self.closed = True


def _secret(tmp_path: Path) -> Path:
    path = tmp_path / "provider.key"
    path.write_text("test-provider-secret", encoding="utf-8")
    path.chmod(0o600)
    return path.resolve()


def _post(tmp_path: Path, **overrides):
    arguments = {
        "allowed_hosts": ["api.example.test"],
        "api_key_file": str(_secret(tmp_path)),
        "request": {"schema_version": "request.v1"},
        "idempotency_key": "a" * 64,
        "timeout_seconds": 2.5,
        "max_request_bytes": 4096,
        "max_response_bytes": 1024,
        "connection_factory": _Connection,
    }
    arguments.update(overrides)
    return post_json("https://api.example.test/v1/advisory", **arguments)


def test_https_transport_uses_verified_tls_and_idempotency(tmp_path: Path) -> None:
    _Connection.instances.clear()
    _Connection.response = _Response()
    assert _post(tmp_path) == {"ok": True}
    connection = _Connection.instances[-1]
    assert connection.context.check_hostname is True
    assert connection.context.verify_mode != 0
    assert connection.timeout == 2.5
    assert connection.request_call[0:2] == ("POST", "/v1/advisory")
    headers = connection.request_call[3]
    assert headers["Accept-Encoding"] == "identity"
    assert headers["Idempotency-Key"] == "a" * 64
    assert headers["Authorization"] == "Bearer test-provider-secret"
    assert connection.closed is True


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (_Response(status=302), AIAdvisoryContractError),
        (_Response(status=429), AIProviderUnavailable),
        (_Response(status=503), AIProviderUnavailable),
        (_Response(content_type="text/html"), AIAdvisoryContractError),
        (_Response(content_encoding="gzip"), AIAdvisoryContractError),
        (_Response(body=b"x" * 1025, content_length="1025"), AIAdvisoryContractError),
    ],
)
def test_https_transport_rejects_redirects_and_unsafe_responses(
    tmp_path: Path, response: _Response, error: type[Exception]
) -> None:
    _Connection.response = response
    with pytest.raises(error):
        _post(tmp_path)


def test_secure_file_requires_absolute_owner_only_non_symlink_path(
    tmp_path: Path,
) -> None:
    secret = _secret(tmp_path)
    assert read_secure_file(str(secret), name="secret") == b"test-provider-secret"
    with pytest.raises(ValueError, match="absolute"):
        read_secure_file("relative.key", name="secret")
    secret.chmod(0o640)
    with pytest.raises(ValueError, match="group or other"):
        read_secure_file(str(secret), name="secret")
    secret.chmod(0o600)
    link = tmp_path / "secret-link"
    link.symlink_to(secret)
    with pytest.raises(ValueError, match="symlink"):
        read_secure_file(str(link.resolve().parent / link.name), name="secret")
    with pytest.raises(ValueError, match="owned"):
        read_secure_file(
            str(secret), name="secret", expected_owner_uid=os.geteuid() + 1
        )


def test_secure_file_reads_open_descriptor_not_replacement(
    tmp_path: Path, monkeypatch
) -> None:
    secret = _secret(tmp_path)
    replacement = tmp_path / "replacement.key"
    replacement.write_text("replacement-provider-secret", encoding="utf-8")
    replacement.chmod(0o600)
    original_fstat = os.fstat
    replaced = False

    def replace_after_open(descriptor):
        nonlocal replaced
        metadata = original_fstat(descriptor)
        if not replaced:
            os.replace(replacement, secret)
            replaced = True
        return metadata

    monkeypatch.setattr(os, "fstat", replace_after_open)
    assert read_secure_file(str(secret), name="secret") == b"test-provider-secret"
    assert secret.read_text(encoding="utf-8") == "replacement-provider-secret"
