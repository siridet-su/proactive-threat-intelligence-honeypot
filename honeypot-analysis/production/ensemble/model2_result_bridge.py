#!/usr/bin/env python3
"""Local-only, exact-session bridge for the protected Model2 V7 result spool."""

from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import sys
from pathlib import Path
from typing import Any, Mapping


sys.path.insert(0, "/opt/honeypot")
from production.ensemble.evidence import (  # noqa: E402
    expected_v5_artifact_sha256, normalize_model2_v5_shadow_result,
)


BRIDGE_REQUEST_SCHEMA = "model2_v5_ensemble_bridge_request.v1"
BRIDGE_RESPONSE_SCHEMA = "model2_v5_ensemble_bridge_response.v1"
MODEL2_V5_RESULT_SCHEMA = "model2_v5_style_unified_production_native_shadow_result.v1"
MODEL2_V5_ARTIFACT_SHA256 = "104d4c77a3e1536b847561abb19fc7c0d6d7dc0111cd98d1ff2d9c9d74a2ed1a"
MODEL2_V5_FEATURE_CONTRACT_SHA256 = "cf985643ce89c3d1f86f6c45943c3ba3af6cf13c60c4b41e215c7c7bc8990a20"
BINDING_SHA256 = "2aa0cfebe1298943517610c3e62e0c9a38651ea93b65747dc69250d814b26c7b"
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESULT_BYTES = 128 * 1024
MAX_RESULT_FILES = 4096


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _response(status: str, *, result: Mapping[str, Any] | None = None, reason: str = "") -> bytes:
    value: dict[str, Any] = {
        "schema_version": BRIDGE_RESPONSE_SCHEMA,
        "status": status,
        "authority": "ADVISORY_ONLY",
    }
    if result is not None:
        value["result"] = dict(result)
    if reason:
        value["reason"] = reason[:160]
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _valid_result(value: Any, *, session_id: str, run_id: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    if _clean(value.get("session_id")) != session_id:
        return False
    if run_id and _clean(value.get("run_id")) != run_id:
        return False
    if (
        _clean(value.get("schema_version")) != MODEL2_V5_RESULT_SCHEMA
        or _clean(value.get("status")) != "VALID_SHADOW"
        or _clean(value.get("availability")) != "AVAILABLE"
        or value.get("authority") != "NON_AUTHORITATIVE_SHADOW_ONLY"
        or value.get("one_model") is not True
        or value.get("one_inference_call") is not True
        or value.get("independent_binary_heads") is not False
        or value.get("argmax_used") is not False
        or value.get("canonical_write_authority") is not False
        or value.get("pcap_binding") != "PASS"
        or value.get("zeek_binding") != "PASS"
        or value.get("feature_materialization") != "PASS"
        or value.get("source_binding") != "PASS"
        or value.get("session_binding") != "PASS"
        or value.get("run_id_binding") != "PASS"
        or value.get("feature_count") != 32
        or value.get("source_feature_count") != 32
        or value.get("zero_fill") is not False
        or value.get("source_ip_only_binding") is not False
        or value.get("cross_session_contamination") != "NO"
        or value.get("binding_contract_sha256") != BINDING_SHA256
    ):
        return False
    binding = {
        field: value.get(field)
        for field in ("session_id", "run_id", "measurement_id", "episode_id")
    }
    try:
        normalized = normalize_model2_v5_shadow_result(
            value,
            binding=binding,
            expected_model_sha256=expected_v5_artifact_sha256(value),
            expected_feature_contract_sha256=MODEL2_V5_FEATURE_CONTRACT_SHA256,
        )
    except (TypeError, ValueError):
        return False
    return normalized.get("available") is True


def _find_result(root: Path, *, session_id: str, run_id: str) -> tuple[str, dict[str, Any] | None]:
    if not root.is_dir() or root.is_symlink():
        return "UNAVAILABLE", None
    try:
        paths = sorted(root.glob("*.json"))
    except OSError:
        return "UNAVAILABLE", None
    if len(paths) > MAX_RESULT_FILES:
        return "UNAVAILABLE", None
    matches: list[dict[str, Any]] = []
    for path in paths:
        try:
            info = path.lstat()
            if not path.is_file() or path.is_symlink() or info.st_size > MAX_RESULT_BYTES:
                continue
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
            continue
        if not isinstance(value, Mapping) or _clean(value.get("session_id")) != session_id:
            continue
        if run_id and _clean(value.get("run_id")) != run_id:
            continue
        matches.append(dict(value))
    if len(matches) != 1:
        return "UNAVAILABLE", None
    value = matches[0]
    if not _valid_result(value, session_id=session_id, run_id=run_id):
        return "UNAVAILABLE", None
    return "AVAILABLE", value


def _handle(line: bytes, root: Path) -> bytes:
    if len(line) > MAX_REQUEST_BYTES:
        return _response("UNAVAILABLE", reason="request_bound_exceeded")
    try:
        request = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _response("UNAVAILABLE", reason="request_invalid")
    if (
        not isinstance(request, Mapping)
        or set(request) != {"schema_version", "session_id", "run_id"}
        or request.get("schema_version") != BRIDGE_REQUEST_SCHEMA
    ):
        return _response("UNAVAILABLE", reason="request_schema_invalid")
    session_id = _clean(request.get("session_id"))
    run_id = _clean(request.get("run_id"))
    if not session_id:
        return _response("UNAVAILABLE", reason="session_id_missing")
    status, result = _find_result(root, session_id=session_id, run_id=run_id)
    return _response(status, result=result, reason="no_unique_valid_result" if result is None else "")


def serve(root: Path, socket_path: Path) -> None:
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists() or socket_path.is_symlink():
        info = socket_path.lstat()
        if not stat.S_ISSOCK(info.st_mode):
            raise RuntimeError("bridge socket path is not a socket")
        socket_path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(socket_path))
        os.chmod(socket_path, 0o660)
        server.listen(16)
        while True:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(1.0)
                data = bytearray()
                try:
                    while len(data) <= MAX_REQUEST_BYTES:
                        chunk = connection.recv(min(4096, MAX_REQUEST_BYTES + 1 - len(data)))
                        if not chunk:
                            break
                        data.extend(chunk)
                        if b"\n" in chunk:
                            break
                    response = _handle(bytes(data).split(b"\n", 1)[0], root)
                except OSError:
                    response = _response("UNAVAILABLE", reason="connection_error")
                try:
                    connection.sendall(response)
                except (BrokenPipeError, ConnectionResetError):
                    # A caller may time out after submitting a complete request.
                    # That must not terminate the long-running bridge process.
                    continue


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    args = parser.parse_args()
    serve(args.results, args.socket)


if __name__ == "__main__":
    main()
