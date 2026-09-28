#!/usr/bin/env python3
"""Local-only, exact-session bridge for the protected Model2 V7 result spool."""

from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping


sys.path.insert(0, "/opt/honeypot")
from production.ensemble.evidence import (  # noqa: E402
    expected_feature_contract_sha256,
    expected_v5_artifact_sha256,
    normalize_model2_v5_shadow_result,
)


BRIDGE_REQUEST_SCHEMA = "model2_v5_ensemble_bridge_request.v1"
BRIDGE_RESPONSE_SCHEMA = "model2_v5_ensemble_bridge_response.v1"
MODEL2_V5_RESULT_SCHEMA = "model2_v5_style_unified_production_native_shadow_result.v1"
MODEL2_V5_ARTIFACT_SHA256 = "104d4c77a3e1536b847561abb19fc7c0d6d7dc0111cd98d1ff2d9c9d74a2ed1a"
MODEL2_V5_FEATURE_CONTRACT_SHA256 = "cf985643ce89c3d1f86f6c45943c3ba3af6cf13c60c4b41e215c7c7bc8990a20"
MODEL2_UNIFIED54_RESULT_SCHEMA = "model2_unified_54f_experimental_shadow_result.v1"
BINDING_SHA256 = "2aa0cfebe1298943517610c3e62e0c9a38651ea93b65747dc69250d814b26c7b"
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESULT_BYTES = 128 * 1024
# The receiver directory is append-only and can legitimately outgrow the old
# 4,096-file per-request scan bound.  Keep a hard upper bound, but index exact
# session identities in memory so normal lookups do not reread every result.
MAX_RESULT_FILES = 65_536


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
        _clean(value.get("schema_version")) not in {MODEL2_V5_RESULT_SCHEMA, MODEL2_UNIFIED54_RESULT_SCHEMA}
        or _clean(value.get("status")) != "VALID_SHADOW"
        or _clean(value.get("availability")) != "AVAILABLE"
        or value.get("authority") != "NON_AUTHORITATIVE_SHADOW_ONLY"
        or value.get("one_model") is not True
        or value.get("one_inference_call") is not True
        or value.get("independent_binary_heads") is not (
            _clean(value.get("schema_version")) == MODEL2_UNIFIED54_RESULT_SCHEMA
        )
        or value.get("argmax_used") is not False
        or value.get("canonical_write_authority") is not False
        or value.get("pcap_binding") != "PASS"
        or value.get("zeek_binding") != "PASS"
        or value.get("feature_materialization") != "PASS"
        or value.get("source_binding") != "PASS"
        or value.get("session_binding") != "PASS"
        or value.get("run_id_binding") != "PASS"
        or value.get("feature_count") != (54 if _clean(value.get("schema_version")) == MODEL2_UNIFIED54_RESULT_SCHEMA else 32)
        or value.get("source_feature_count") != (54 if _clean(value.get("schema_version")) == MODEL2_UNIFIED54_RESULT_SCHEMA else 32)
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
            expected_feature_contract_sha256=expected_feature_contract_sha256(value),
        )
    except (TypeError, ValueError):
        return False
    return normalized.get("available") is True


class _ResultIndex:
    """Bounded exact-session index for the append-only result directory."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._files: dict[str, tuple[tuple[int, int, int], str]] = {}
        self._by_session: dict[str, set[str]] = defaultdict(set)

    def _remove(self, name: str) -> None:
        previous = self._files.pop(name, None)
        if previous is None:
            return
        session_id = previous[1]
        names = self._by_session.get(session_id)
        if names is None:
            return
        names.discard(name)
        if not names:
            self._by_session.pop(session_id, None)

    @staticmethod
    def _read_session_id(path: Path, info: os.stat_result) -> str:
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RESULT_BYTES:
            return ""
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
            return ""
        return _clean(value.get("session_id")) if isinstance(value, Mapping) else ""

    def refresh(self) -> bool:
        if not self.root.is_dir() or self.root.is_symlink():
            return False
        try:
            entries = [
                entry
                for entry in os.scandir(self.root)
                if entry.name.endswith(".json")
            ]
        except OSError:
            return False
        if len(entries) > MAX_RESULT_FILES:
            return False

        seen: set[str] = set()
        for entry in entries:
            name = entry.name
            seen.add(name)
            try:
                if entry.is_symlink():
                    self._remove(name)
                    continue
                info = entry.stat(follow_symlinks=False)
            except OSError:
                self._remove(name)
                continue
            signature = (int(info.st_ino), int(info.st_mtime_ns), int(info.st_size))
            previous = self._files.get(name)
            if previous is not None and previous[0] == signature:
                continue
            self._remove(name)
            session_id = self._read_session_id(Path(entry.path), info)
            if not session_id:
                continue
            self._files[name] = (signature, session_id)
            self._by_session[session_id].add(name)

        for name in set(self._files).difference(seen):
            self._remove(name)
        return True

    def paths_for(self, session_id: str) -> list[Path]:
        return [self.root / name for name in sorted(self._by_session.get(session_id, set()))]


def _find_result(
    root: Path,
    *,
    session_id: str,
    run_id: str,
    index: _ResultIndex | None = None,
) -> tuple[str, dict[str, Any] | None]:
    if not root.is_dir() or root.is_symlink():
        return "UNAVAILABLE", None
    selected_index = index or _ResultIndex(root)
    if selected_index.root != root or not selected_index.refresh():
        return "UNAVAILABLE", None
    matches: list[dict[str, Any]] = []
    for path in selected_index.paths_for(session_id):
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


def _handle(line: bytes, root: Path, *, index: _ResultIndex | None = None) -> bytes:
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
    status, result = _find_result(
        root,
        session_id=session_id,
        run_id=run_id,
        index=index,
    )
    return _response(status, result=result, reason="no_unique_valid_result" if result is None else "")


def serve(root: Path, socket_path: Path) -> None:
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists() or socket_path.is_symlink():
        info = socket_path.lstat()
        if not stat.S_ISSOCK(info.st_mode):
            raise RuntimeError("bridge socket path is not a socket")
        socket_path.unlink()
    result_index = _ResultIndex(root)
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
                    response = _handle(
                        bytes(data).split(b"\n", 1)[0],
                        root,
                        index=result_index,
                    )
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
