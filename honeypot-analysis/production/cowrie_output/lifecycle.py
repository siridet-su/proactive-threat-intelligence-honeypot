"""Bounded, privacy-safe lifecycle state for the Cowrie JSON output plugin."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "cowrie_output_lifecycle.v1"
MAX_SEQUENCE = 2**63 - 1
PHASES = frozenset(
    {
        "class_discovery",
        "constructor",
        "start",
        "file_open",
        "registration",
        "invocation",
        "serialization",
        "write",
        "flush",
        "stop",
    }
)
EVENT_CATEGORIES = frozenset(
    {
        "authentication",
        "client",
        "command",
        "diagnostic",
        "lifecycle",
        "network",
        "session",
        "transfer",
        "unavailable",
    }
)
RESULTS = frozenset({"attempted", "failed", "succeeded"})
EXCEPTION_CATEGORIES = frozenset(
    {
        "none",
        "class_discovery",
        "constructor",
        "start",
        "registration",
        "serialization",
        "file_open",
        "write",
        "flush",
        "state_unavailable",
    }
)
OUTPUT_INODE_CATEGORIES = frozenset(
    {"unavailable", "canonical_active", "rotated_open", "non_regular"}
)
_STATE_KEYS = frozenset(
    {
        "schema_version",
        "component_id",
        "source_revision",
        "module_path_category",
        "module_sha256",
        "class_name",
        "class_discovered",
        "constructor_entered",
        "constructor_completed",
        "start_entered",
        "start_completed",
        "observer_registered",
        "write_invocations",
        "serialization_attempts",
        "serialization_successes",
        "write_attempts",
        "write_successes",
        "flush_attempts",
        "flush_successes",
        "file_open_attempts",
        "file_open_successes",
        "last_phase",
        "last_result",
        "last_event_category",
        "last_event_id_sha256",
        "last_exception_category",
        "output_inode_category",
        "sequence",
        "process_pid",
        "lifecycle_timestamp_ns",
        "state_sha256",
    }
)


class LifecycleStateError(ValueError):
    """Lifecycle state is outside the closed diagnostic contract."""


def _canonical(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _state_digest(document: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in document.items() if key != "state_sha256"}
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def initial_state(
    *, component_id: str, source_revision: str, module_sha256: str
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "component_id": component_id,
        "source_revision": source_revision,
        "module_path_category": "manifest_bound_release",
        "module_sha256": module_sha256,
        "class_name": "Output",
        "class_discovered": False,
        "constructor_entered": False,
        "constructor_completed": False,
        "start_entered": False,
        "start_completed": False,
        "observer_registered": False,
        "write_invocations": 0,
        "serialization_attempts": 0,
        "serialization_successes": 0,
        "write_attempts": 0,
        "write_successes": 0,
        "flush_attempts": 0,
        "flush_successes": 0,
        "file_open_attempts": 0,
        "file_open_successes": 0,
        "last_phase": "class_discovery",
        "last_result": "attempted",
        "last_event_category": "unavailable",
        "last_event_id_sha256": "unavailable",
        "last_exception_category": "none",
        "output_inode_category": "unavailable",
        "sequence": 0,
        "process_pid": os.getpid(),
        "lifecycle_timestamp_ns": time.time_ns(),
        "state_sha256": "",
    }


def validate_lifecycle_state(document: Any) -> dict[str, Any]:
    if not isinstance(document, Mapping) or set(document) != _STATE_KEYS:
        raise LifecycleStateError("lifecycle state keys are invalid")
    state = dict(document)
    if state["schema_version"] != SCHEMA_VERSION:
        raise LifecycleStateError("lifecycle state schema is invalid")
    if (
        not isinstance(state["component_id"], str)
        or re.fullmatch(r"cowrie_output_[0-9a-f]{32}", state["component_id"])
        is None
        or not isinstance(state["source_revision"], str)
        or re.fullmatch(r"[0-9a-f]{40}", state["source_revision"]) is None
        or state["module_path_category"] != "manifest_bound_release"
        or not isinstance(state["module_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", state["module_sha256"]) is None
        or state["class_name"] != "Output"
    ):
        raise LifecycleStateError("lifecycle provenance is invalid")
    for field in (
        "class_discovered",
        "constructor_entered",
        "constructor_completed",
        "start_entered",
        "start_completed",
        "observer_registered",
    ):
        if not isinstance(state[field], bool):
            raise LifecycleStateError(f"lifecycle boolean is invalid: {field}")
    for field in (
        "write_invocations",
        "serialization_attempts",
        "serialization_successes",
        "write_attempts",
        "write_successes",
        "flush_attempts",
        "flush_successes",
        "file_open_attempts",
        "file_open_successes",
        "sequence",
        "process_pid",
        "lifecycle_timestamp_ns",
    ):
        value = state[field]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
            or value > MAX_SEQUENCE
        ):
            raise LifecycleStateError(f"lifecycle counter is invalid: {field}")
    if state["process_pid"] <= 0 or state["lifecycle_timestamp_ns"] <= 0:
        raise LifecycleStateError("lifecycle process identity is invalid")
    if state["last_phase"] not in PHASES or state["last_result"] not in RESULTS:
        raise LifecycleStateError("lifecycle phase or result is invalid")
    if state["last_event_category"] not in EVENT_CATEGORIES:
        raise LifecycleStateError("lifecycle event category is invalid")
    event_hash = state["last_event_id_sha256"]
    if event_hash != "unavailable" and (
        not isinstance(event_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", event_hash) is None
    ):
        raise LifecycleStateError("lifecycle event hash is invalid")
    if state["last_exception_category"] not in EXCEPTION_CATEGORIES:
        raise LifecycleStateError("lifecycle exception category is invalid")
    if state["output_inode_category"] not in OUTPUT_INODE_CATEGORIES:
        raise LifecycleStateError("lifecycle output inode category is invalid")
    for successes, attempts in (
        ("serialization_successes", "serialization_attempts"),
        ("write_successes", "write_attempts"),
        ("flush_successes", "flush_attempts"),
        ("file_open_successes", "file_open_attempts"),
    ):
        if state[successes] > state[attempts]:
            raise LifecycleStateError("lifecycle successes exceed attempts")
    if state["constructor_completed"] and not state["constructor_entered"]:
        raise LifecycleStateError("constructor completion lacks entry")
    if state["start_completed"] and not state["start_entered"]:
        raise LifecycleStateError("start completion lacks entry")
    if state["observer_registered"] and not state["constructor_completed"]:
        raise LifecycleStateError("observer registration lacks construction")
    if state["state_sha256"] != _state_digest(state):
        raise LifecycleStateError("lifecycle state digest is invalid")
    return state


def load_lifecycle_state(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise LifecycleStateError("lifecycle state is not a regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise LifecycleStateError("lifecycle state mode is invalid")
        document = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleStateError("lifecycle state is unavailable") from exc
    return validate_lifecycle_state(document)


def write_lifecycle_state(path: Path, document: Mapping[str, Any]) -> dict[str, Any]:
    state = dict(document)
    state["state_sha256"] = _state_digest(state)
    validated = validate_lifecycle_state(state)
    parent = path.parent
    metadata = parent.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or parent.is_symlink()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
    ):
        raise LifecycleStateError("lifecycle state directory is unsafe")
    if path.exists() or path.is_symlink():
        existing = path.lstat()
        if (
            not stat.S_ISREG(existing.st_mode)
            or path.is_symlink()
            or stat.S_IMODE(existing.st_mode) != 0o600
            or existing.st_uid != metadata.st_uid
            or existing.st_gid != metadata.st_gid
        ):
            raise LifecycleStateError("existing lifecycle state is unsafe")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".cowrie-output-lifecycle.", dir=parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_canonical(validated) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise
    return validated


def update_lifecycle_state(
    path: Path,
    *,
    component_id: str,
    source_revision: str,
    module_sha256: str,
    phase: str,
    result: str,
    event_category: str = "unavailable",
    event_id_sha256: str = "unavailable",
    exception_category: str = "none",
    output_inode_category: str = "unavailable",
    flags: Mapping[str, bool] | None = None,
    increments: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    if phase not in PHASES or result not in RESULTS:
        raise LifecycleStateError("lifecycle update phase or result is invalid")
    if event_category not in EVENT_CATEGORIES:
        raise LifecycleStateError("lifecycle update event category is invalid")
    if exception_category not in EXCEPTION_CATEGORIES:
        raise LifecycleStateError("lifecycle update exception category is invalid")
    if output_inode_category not in OUTPUT_INODE_CATEGORIES:
        raise LifecycleStateError("lifecycle update inode category is invalid")
    try:
        state = load_lifecycle_state(path)
        if (
            state["component_id"] != component_id
            or state["source_revision"] != source_revision
            or state["module_sha256"] != module_sha256
            or state["process_pid"] != os.getpid()
        ):
            state = initial_state(
                component_id=component_id,
                source_revision=source_revision,
                module_sha256=module_sha256,
            )
    except LifecycleStateError:
        state = initial_state(
            component_id=component_id,
            source_revision=source_revision,
            module_sha256=module_sha256,
        )
    for field, value in (flags or {}).items():
        if field not in {
            "class_discovered",
            "constructor_entered",
            "constructor_completed",
            "start_entered",
            "start_completed",
            "observer_registered",
        } or not isinstance(value, bool):
            raise LifecycleStateError("lifecycle flag update is invalid")
        state[field] = value
    for field, value in (increments or {}).items():
        if field not in {
            "write_invocations",
            "serialization_attempts",
            "serialization_successes",
            "write_attempts",
            "write_successes",
            "flush_attempts",
            "flush_successes",
            "file_open_attempts",
            "file_open_successes",
        } or not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise LifecycleStateError("lifecycle counter update is invalid")
        state[field] = min(MAX_SEQUENCE, int(state[field]) + value)
    state.update(
        {
            "last_phase": phase,
            "last_result": result,
            "last_event_category": event_category,
            "last_event_id_sha256": event_id_sha256,
            "last_exception_category": exception_category,
            "output_inode_category": output_inode_category,
            "sequence": min(MAX_SEQUENCE, int(state["sequence"]) + 1),
            "process_pid": os.getpid(),
            "lifecycle_timestamp_ns": time.time_ns(),
        }
    )
    return write_lifecycle_state(path, state)
