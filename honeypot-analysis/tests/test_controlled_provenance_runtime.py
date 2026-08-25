from __future__ import annotations

import ast
import inspect
import json

import pytest

from production import controlled_provenance_runtime as runtime


def test_controlled_provenance_requires_exact_server_owned_pair() -> None:
    binding = {
        "enabled": True,
        "sensor_ids": ["sensor-approved"],
        "source_ips": ["100.64.0.10"],
        "marker": runtime.PROVENANCE_MARKER,
    }
    assert runtime._derive(binding, "sensor-approved", "100.64.0.10") == {
        "session_source": runtime.SESSION_SOURCE_E2E_TEST,
        "provenance_marker": runtime.PROVENANCE_MARKER,
    }
    for sensor_id, source_ip in (
        ("sensor-other", "100.64.0.10"),
        ("sensor-approved", "100.64.0.11"),
        (" sensor-approved", "100.64.0.10"),
    ):
        assert runtime._derive(binding, sensor_id, source_ip) == {
            "session_source": runtime.SESSION_SOURCE_PRODUCTION_LIVE,
            "provenance_marker": "",
        }


def test_binding_loader_rejects_global_source_address(tmp_path, monkeypatch) -> None:
    path = tmp_path / "controlled.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": runtime.SCHEMA_VERSION,
                "enabled": True,
                "sensor_ids": ["sensor-approved"],
                "source_ips": ["8.8.8.8"],
                "marker": runtime.PROVENANCE_MARKER,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CONTROLLED_PROVENANCE_CONFIG_FILE", str(path))
    with pytest.raises(RuntimeError, match="must not be global"):
        runtime._load_binding()


def test_terminal_wrapper_forwards_evidence_cutoff_keyword() -> None:
    tree = ast.parse(inspect.getsource(runtime._patch_runtime))
    patched_close = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "patched_close"
    )
    assert [argument.arg for argument in patched_close.args.args] == [
        "self",
        "state",
        "evidence_cutoff",
    ]
    forwarded_calls = [
        node
        for node in ast.walk(patched_close)
        if isinstance(node, ast.Call)
        and any(keyword.arg == "evidence_cutoff" for keyword in node.keywords)
    ]
    assert len(forwarded_calls) == 2

