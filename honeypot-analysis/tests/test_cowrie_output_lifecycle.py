from __future__ import annotations

import hashlib
import json
import os
import stat
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from production.cowrie_output.lifecycle import (
    LifecycleStateError,
    load_lifecycle_state,
    update_lifecycle_state,
    validate_lifecycle_state,
)
from production.cowrie_output.runtime import CowrieOutputBoundaryError
from production.tools import cowrie_output_integration as integration


REVISION = "a" * 40
COMPONENT_ID = "cowrie_output_" + "b" * 32
MODULE_SHA256 = "c" * 64


def _state_path(tmp_path: Path) -> Path:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    return directory / "cowrie-output-lifecycle.json"


def test_lifecycle_state_is_owner_only_deterministic_and_integrity_bound(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    state = update_lifecycle_state(
        path,
        component_id=COMPONENT_ID,
        source_revision=REVISION,
        module_sha256=MODULE_SHA256,
        phase="class_discovery",
        result="succeeded",
        flags={"class_discovered": True},
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_lifecycle_state(path) == state
    assert json.loads(path.read_bytes()) == state
    assert state["state_sha256"] == hashlib.sha256(
        json.dumps(
            {k: v for k, v in state.items() if k != "state_sha256"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("component_id", "cowrie_output_" + "z" * 32),
        ("source_revision", "z" * 40),
        ("module_sha256", "z" * 64),
        ("last_phase", "invented"),
        ("last_result", "maybe"),
        ("last_event_category", "credential"),
        ("last_exception_category", "traceback"),
        ("output_inode_category", "secret-path"),
        ("observer_registered", "yes"),
        ("write_invocations", -1),
    ],
)
def test_lifecycle_contract_rejects_invented_values_even_with_recomputed_hash(
    tmp_path: Path, field: str, value: object
) -> None:
    path = _state_path(tmp_path)
    state = update_lifecycle_state(
        path,
        component_id=COMPONENT_ID,
        source_revision=REVISION,
        module_sha256=MODULE_SHA256,
        phase="class_discovery",
        result="succeeded",
        flags={"class_discovered": True},
    )
    state[field] = value
    unsigned = {k: v for k, v in state.items() if k != "state_sha256"}
    state["state_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(LifecycleStateError):
        validate_lifecycle_state(state)


def test_lifecycle_state_rejects_symlink_and_open_mode(tmp_path: Path) -> None:
    path = _state_path(tmp_path)
    update_lifecycle_state(
        path,
        component_id=COMPONENT_ID,
        source_revision=REVISION,
        module_sha256=MODULE_SHA256,
        phase="class_discovery",
        result="succeeded",
    )
    path.chmod(0o640)
    with pytest.raises(LifecycleStateError):
        load_lifecycle_state(path)
    path.chmod(0o600)
    target = path.with_suffix(".target")
    path.replace(target)
    path.symlink_to(target)
    with pytest.raises(LifecycleStateError):
        load_lifecycle_state(path)
    with pytest.raises(LifecycleStateError):
        update_lifecycle_state(
            path,
            component_id=COMPONENT_ID,
            source_revision=REVISION,
            module_sha256=MODULE_SHA256,
            phase="invocation",
            result="succeeded",
        )
    assert path.is_symlink()


def test_lifecycle_diagnostics_never_accept_raw_event_or_exception_fields(
    tmp_path: Path,
) -> None:
    path = _state_path(tmp_path)
    with pytest.raises(TypeError):
        update_lifecycle_state(  # type: ignore[call-arg]
            path,
            component_id=COMPONENT_ID,
            source_revision=REVISION,
            module_sha256=MODULE_SHA256,
            phase="invocation",
            result="failed",
            raw_event={"password": "must-not-persist"},
        )
    assert not path.exists()


def _fake_plugin_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "runtime" / "src"
    base_path = source / "cowrie/core/output.py"
    loader_path = source / "twisted/plugins/cowrie_plugin.py"
    base_path.parent.mkdir(parents=True)
    loader_path.parent.mkdir(parents=True)
    base_path.write_text("output-base\n", encoding="utf-8")
    loader_path.write_text("plugin-loader\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    module_path = bundle / "production/cowrie_output/sanitized_jsonlog.py"
    module_path.parent.mkdir(parents=True)
    module_path.write_text("manifest-bound-module\n", encoding="utf-8")
    logs = tmp_path / "cowrie" / "var/log/cowrie"
    state_dir = tmp_path / "cowrie" / "var/lib/cowrie"
    logs.mkdir(parents=True, mode=0o700)
    state_dir.mkdir(parents=True, mode=0o700)

    class BaseOutput:
        pass

    class Output(BaseOutput):
        pass

    Output.__module__ = "cowrie.output.sanitizedjson"

    class FakeConfig:
        @staticmethod
        def sections():
            return ["output_jsonlog", "output_sanitizedjson"]

        @staticmethod
        def getboolean(section, option, fallback=False):
            return section == "output_sanitizedjson" and option == "enabled"

        @staticmethod
        def get(section, option, fallback=""):
            values = {
                ("output_sanitizedjson", "logfile"): str(logs / "cowrie.json"),
                ("output_sanitizedjson", "lifecycle_state"): str(
                    state_dir / "cowrie-output-lifecycle.json"
                ),
            }
            return values.get((section, option), fallback)

    cowrie = types.ModuleType("cowrie")
    core = types.ModuleType("cowrie.core")
    base = types.ModuleType("cowrie.core.output")
    base.Output = BaseOutput
    base.__file__ = str(base_path)
    config = types.ModuleType("cowrie.core.config")
    config.CowrieConfig = FakeConfig
    output_package = types.ModuleType("cowrie.output")
    plugin = types.ModuleType("cowrie.output.sanitizedjson")
    plugin.Output = Output
    plugin.__file__ = str(module_path)
    monkeypatch.setitem(__import__("sys").modules, "cowrie", cowrie)
    monkeypatch.setitem(__import__("sys").modules, "cowrie.core", core)
    monkeypatch.setitem(__import__("sys").modules, "cowrie.core.output", base)
    monkeypatch.setitem(__import__("sys").modules, "cowrie.core.config", config)
    monkeypatch.setitem(__import__("sys").modules, "cowrie.output", output_package)
    monkeypatch.setitem(
        __import__("sys").modules, "cowrie.output.sanitizedjson", plugin
    )
    monkeypatch.setitem(
        integration.DEPLOYMENT_CONTRACT["compatibility"],
        "cowrie_output_base_sha256",
        hashlib.sha256(base_path.read_bytes()).hexdigest(),
    )
    monkeypatch.setitem(
        integration.DEPLOYMENT_CONTRACT["compatibility"],
        "cowrie_output_loader_sha256",
        hashlib.sha256(loader_path.read_bytes()).hexdigest(),
    )
    monkeypatch.setenv("HONEYPOT_COWRIE_ROOT", str(tmp_path / "cowrie"))
    boundary = SimpleNamespace(
        bundle_root=bundle,
        module_sha256=hashlib.sha256(module_path.read_bytes()).hexdigest(),
        json_log_path=logs / "cowrie.json",
        lifecycle_state_path=state_dir / "cowrie-output-lifecycle.json",
        component_id=COMPONENT_ID,
        git_revision=REVISION,
    )
    return boundary, plugin, FakeConfig


def test_plugin_readiness_binds_effective_loader_class_paths_and_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary, _plugin, _config = _fake_plugin_runtime(tmp_path, monkeypatch)
    receipt = integration.inspect_plugin_readiness(boundary, write_state=True)
    assert receipt["status"] == "ready"
    assert receipt["class_discovered"] is True
    assert receipt["fake_event_created"] is False
    state = load_lifecycle_state(boundary.lifecycle_state_path)
    assert state["class_discovered"] is True
    assert state["write_invocations"] == 0


@pytest.mark.parametrize("defect", ["wrong_hash", "class_missing", "class_abstract"])
def test_plugin_readiness_fails_closed_for_discovery_defects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str
) -> None:
    boundary, plugin, _config = _fake_plugin_runtime(tmp_path, monkeypatch)
    if defect == "wrong_hash":
        boundary.module_sha256 = "0" * 64
    elif defect == "class_missing":
        del plugin.Output
    else:
        plugin.Output.__abstractmethods__ = frozenset({"write"})
    with pytest.raises(CowrieOutputBoundaryError):
        integration.inspect_plugin_readiness(boundary)


def test_live_readiness_requires_exact_process_and_complete_registration(
    tmp_path: Path
) -> None:
    path = _state_path(tmp_path)
    state = update_lifecycle_state(
        path,
        component_id=COMPONENT_ID,
        source_revision=REVISION,
        module_sha256=MODULE_SHA256,
        phase="registration",
        result="succeeded",
        flags={
            "class_discovered": True,
            "constructor_entered": True,
            "constructor_completed": True,
            "start_entered": True,
            "start_completed": True,
            "observer_registered": True,
        },
    )
    boundary = SimpleNamespace(
        lifecycle_state_path=path,
        component_id=COMPONENT_ID,
        git_revision=REVISION,
        module_sha256=MODULE_SHA256,
    )
    receipt = integration.validate_live_readiness(
        boundary, expected_pid=os.getpid()
    )
    assert receipt["state_sha256"] == state["state_sha256"]
    with pytest.raises(CowrieOutputBoundaryError):
        integration.validate_live_readiness(
            boundary, expected_pid=os.getpid() + 1
        )


def test_live_readiness_rejects_missing_lifecycle_steps(tmp_path: Path) -> None:
    path = _state_path(tmp_path)
    update_lifecycle_state(
        path,
        component_id=COMPONENT_ID,
        source_revision=REVISION,
        module_sha256=MODULE_SHA256,
        phase="start",
        result="succeeded",
        flags={
            "class_discovered": True,
            "constructor_entered": True,
            "constructor_completed": True,
            "start_entered": True,
            "start_completed": True,
        },
    )
    boundary = SimpleNamespace(
        lifecycle_state_path=path,
        component_id=COMPONENT_ID,
        git_revision=REVISION,
        module_sha256=MODULE_SHA256,
    )
    with pytest.raises(CowrieOutputBoundaryError):
        integration.validate_live_readiness(boundary, expected_pid=os.getpid())
