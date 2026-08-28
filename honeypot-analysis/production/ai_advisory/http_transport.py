"""Strict, provider-neutral HTTPS JSON transport for future reviewed adapters."""

from __future__ import annotations

import http.client
import json
import ssl
from typing import Any, Callable, Dict, Mapping

from production.ai_advisory.contracts import AIAdvisoryContractError
from production.ai_advisory.provider import AIProviderUnavailable
from production.ai_advisory.security import read_secure_utf8, validate_https_endpoint
from production.utils.serialization import stable_json


ConnectionFactory = Callable[..., http.client.HTTPSConnection]


def post_json(
    endpoint: str,
    *,
    allowed_hosts: list[str],
    api_key_file: str,
    request: Mapping[str, Any],
    idempotency_key: str,
    timeout_seconds: float,
    max_request_bytes: int,
    max_response_bytes: int,
    connection_factory: ConnectionFactory = http.client.HTTPSConnection,
) -> Dict[str, Any]:
    """POST one bounded JSON object without redirects or compression."""

    parsed = validate_https_endpoint(endpoint, allowed_hosts)
    if float(timeout_seconds) <= 0:
        raise ValueError("AI provider timeout must be positive")
    if int(max_request_bytes) < 1 or int(max_response_bytes) < 1:
        raise ValueError("AI provider byte limits must be positive")
    if not idempotency_key or len(idempotency_key) > 256:
        raise ValueError("AI provider idempotency key is invalid")
    body = stable_json(dict(request)).encode("utf-8")
    if len(body) > int(max_request_bytes):
        raise AIAdvisoryContractError("provider request exceeds the configured limit")
    token = read_secure_utf8(
        api_key_file,
        name="AI_ADVISORY_API_KEY_FILE",
        max_bytes=8192,
    )
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    target = parsed.path or "/"
    connection: http.client.HTTPSConnection | None = None
    try:
        connection = connection_factory(
            parsed.hostname,
            parsed.port or 443,
            timeout=float(timeout_seconds),
            context=context,
        )
        connection.request(
            "POST",
            target,
            body=body,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Idempotency-Key": idempotency_key,
            },
        )
        response = connection.getresponse()
        if 300 <= response.status < 400:
            response.read(min(int(max_response_bytes), 4096) + 1)
            raise AIAdvisoryContractError("provider redirects are prohibited")
        if response.status == 429 or 500 <= response.status < 600:
            response.read(min(int(max_response_bytes), 4096) + 1)
            raise AIProviderUnavailable("provider returned a retryable status")
        if response.status < 200 or response.status >= 300:
            response.read(min(int(max_response_bytes), 4096) + 1)
            raise AIAdvisoryContractError("provider returned a non-success status")
        content_encoding = str(response.getheader("Content-Encoding") or "identity").lower()
        if content_encoding not in {"", "identity"}:
            raise AIAdvisoryContractError("compressed provider responses are prohibited")
        content_type = str(response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/json" and not content_type.endswith("+json"):
            raise AIAdvisoryContractError("provider response content type is invalid")
        declared_length = response.getheader("Content-Length")
        if declared_length is not None:
            try:
                parsed_length = int(declared_length)
                if parsed_length < 0:
                    raise ValueError
                if parsed_length > int(max_response_bytes):
                    raise AIAdvisoryContractError("provider response exceeds the configured limit")
            except ValueError as exc:
                raise AIAdvisoryContractError("provider content length is invalid") from exc
        raw = response.read(int(max_response_bytes) + 1)
        if len(raw) > int(max_response_bytes):
            raise AIAdvisoryContractError("provider response exceeds the configured limit")
        try:
            loaded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AIAdvisoryContractError("provider response is not valid JSON") from exc
        if not isinstance(loaded, dict):
            raise AIAdvisoryContractError("provider response must be an object")
        return loaded
    except (TimeoutError, OSError, http.client.HTTPException) as exc:
        raise AIProviderUnavailable("provider transport is unavailable") from exc
    finally:
        if connection is not None:
            connection.close()
