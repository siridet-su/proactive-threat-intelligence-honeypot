"""Canonical privacy projection for generated report artifacts.

The report pipeline intentionally retains a separate authenticated internal
monitor view for exact command text.  Every public/generated artifact must use
this projection after the general sensitive-data redactor.  It is deliberately
key- and container-aware: evidence references, timestamps, counts, tactics and
other provenance remain intact while command-bearing values are replaced with
the stable redaction marker.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from production.utils.sensitive_data import REDACTION_MARKER


_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")

# These are the command-bearing fields currently emitted by the report,
# correlation and compatibility bridges.  The token checks below also cover
# future names such as ``raw_command_text`` and ``command_map``.
_COMMAND_KEY_NAMES = {
    "command",
    "commands",
    "cmd",
    "input",
    "inputs",
    "raw_command",
    "original_command",
    "command_text",
    "command_line",
    "command_lines",
    "chain",
    "chain_str",
    "command_map",
    "ttp_command_map",
    "bpg",
    "bpg_list",
}

# A compatibility/audit container may gain nested wrappers over time.  Once
# inside one of these containers we recurse through every mapping/list and
# still apply the command-key rules at every depth.
_CONTEXT_KEY_PARTS = (
    "compatibility",
    "audit_only",
    "bpg",
    "command_map",
    "ttp_command_map",
)


def _normalized_key(value: Any) -> str:
    return _NORMALIZE_RE.sub("_", str(value or "").lower()).strip("_")


def _is_command_key(value: Any) -> bool:
    normalized = _normalized_key(value)
    if not normalized:
        return False
    if normalized in _COMMAND_KEY_NAMES:
        return True
    parts = set(normalized.split("_"))
    # ``command_outcome``, ``command_index`` and similar canonical metadata
    # are not command text and must remain intact (especially inside the
    # content-addressed v4 evidence snapshot).
    if normalized.startswith("command_"):
        suffix = normalized[len("command_"):]
        return suffix in {
            "text",
            "line",
            "lines",
            "input",
            "value",
            "raw",
            "string",
            "map",
            "chain",
        }
    # Catch renamed fields such as ``raw_command_text`` while avoiding generic
    # command metadata keys.
    if "command" in parts:
        return bool(parts & {"text", "line", "lines", "input", "value", "raw"})
    if "cmd" in parts:
        return bool(parts & {"text", "line", "lines", "input", "value", "raw"})
    return normalized.startswith("input_") or normalized.endswith("_input")


def _sanitize_node(value: Any, *, key: str = "", command_value: bool = False) -> Any:
    """Recursively sanitize one JSON-safe value without dropping containers."""

    if isinstance(value, Mapping):
        result: dict[Any, Any] = {}
        for raw_key, child in value.items():
            child_key = str(raw_key)
            # A command-bearing mapping may contain metadata (for example a
            # BPG session name and depth) alongside its command list.  Do not
            # redact every scalar in the mapping; recurse and identify the
            # actual command fields at each level.
            child_command = _is_command_key(child_key)
            result[raw_key] = _sanitize_node(
                child,
                key=child_key,
                command_value=child_command,
            )
        return result
    if isinstance(value, (list, tuple)):
        # A command-bearing list (commands, chain, bpg_list, etc.) keeps its
        # item count and object structure, but scalar command text is replaced.
        return [
            _sanitize_node(
                item,
                key=key,
                command_value=(
                    command_value
                    if not isinstance(item, Mapping)
                    else False
                ),
            )
            for item in value
        ]
    if command_value and isinstance(value, str):
        return REDACTION_MARKER
    return value


def sanitize_artifact_boundary(value: Any) -> Any:
    """Return a stable, shape-preserving artifact-safe copy.

    The function is idempotent and never mutates its input.  General redaction
    remains the caller's first pass; this pass specifically closes the command
    text boundary for nested compatibility and audit-only data.
    """

    return _sanitize_node(deepcopy(value))


__all__ = ["sanitize_artifact_boundary"]
