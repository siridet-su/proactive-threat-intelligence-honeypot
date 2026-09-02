"""Configurable, fail-closed collection lifecycle policy for cold archives."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


LIFECYCLE_POLICY_VERSION = "mongo_pi_archive_lifecycle_policy.v1"
LIFECYCLE_CLASSES = frozenset(
    {
        "ARCHIVE_ELIGIBLE_HISTORICAL",
        "HOT_OPERATIONAL_STATE",
        "LONG_TERM_SMALL_METADATA",
        "RECOMPUTABLE_DERIVED",
        "SPECIAL_REVIEW_REQUIRED",
        "NEVER_AUTOMATICALLY_PURGE",
    }
)


class LifecyclePolicyError(ValueError):
    pass


def load_archive_lifecycle_policy(path: str | Path) -> dict[str, Any]:
    selected = Path(path)
    try:
        document = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LifecyclePolicyError("archive lifecycle policy is unreadable") from exc
    validate_archive_lifecycle_policy(document)
    return document


def validate_archive_lifecycle_policy(document: Any) -> None:
    if not isinstance(document, Mapping):
        raise LifecyclePolicyError("archive lifecycle policy must be an object")
    if document.get("schema_version") != LIFECYCLE_POLICY_VERSION:
        raise LifecyclePolicyError("unsupported archive lifecycle policy version")
    thresholds = document.get("capacity_thresholds")
    if not isinstance(thresholds, Mapping):
        raise LifecyclePolicyError("capacity thresholds are required")
    values = [float(thresholds.get(name, -1)) for name in ("warning", "critical", "emergency")]
    if not all(0 < value < 1 for value in values) or values != sorted(values):
        raise LifecyclePolicyError("capacity thresholds must be ascending fractions")
    default_window = document.get("default_hot_window_days")
    if default_window is not None and (
        not isinstance(default_window, int) or isinstance(default_window, bool) or default_window < 0
    ):
        raise LifecyclePolicyError("default hot window must be a non-negative integer or null")
    collections = document.get("collections")
    if not isinstance(collections, Mapping) or not collections:
        raise LifecyclePolicyError("collection lifecycle overrides are required")
    for name, value in collections.items():
        if not isinstance(name, str) or not name:
            raise LifecyclePolicyError("collection lifecycle name is invalid")
        if not isinstance(value, Mapping):
            raise LifecyclePolicyError(f"lifecycle policy for {name} must be an object")
        classification = value.get("classification")
        if classification not in LIFECYCLE_CLASSES:
            raise LifecyclePolicyError(f"lifecycle classification for {name} is invalid")
        window = value.get("hot_window_days", default_window)
        if window is not None and (
            not isinstance(window, int) or isinstance(window, bool) or window < 0
        ):
            raise LifecyclePolicyError(f"hot window for {name} must be a non-negative integer or null")
        for key in ("archive_eligible", "purge_eligible", "reconstructable"):
            if not isinstance(value.get(key), bool):
                raise LifecyclePolicyError(f"{name}.{key} must be boolean")
        dependencies = value.get("dependencies", [])
        if not isinstance(dependencies, list) or not all(isinstance(item, str) for item in dependencies):
            raise LifecyclePolicyError(f"{name}.dependencies must be a string list")


def lifecycle_gate(
    policy: Mapping[str, Any],
    collection: str,
    observed_state: Mapping[str, Any],
) -> dict[str, Any]:
    """Return explicit lifecycle evidence; no missing state is treated as safe."""

    declarations = policy.get("collections") or {}
    declaration = declarations.get(collection)
    if not isinstance(declaration, Mapping):
        return {
            "collection": collection,
            "eligible": False,
            "status": "UNRESOLVED_COLLECTION_POLICY",
            "missing": ["collection_policy"],
        }
    required = list(declaration.get("required_terminal_fields") or [])
    missing = [field for field in required if observed_state.get(field) is not True]
    eligible = bool(declaration.get("archive_eligible")) and not missing
    return {
        "collection": collection,
        "classification": declaration.get("classification"),
        "eligible": eligible,
        "status": "LIFECYCLE_SAFE" if eligible else "LIFECYCLE_UNSAFE_OR_UNRESOLVED",
        "required_terminal_fields": required,
        "observed_state": {field: bool(observed_state.get(field)) for field in required},
        "missing": missing,
        "dependencies": list(declaration.get("dependencies") or []),
        "hot_window_days": declaration.get(
            "hot_window_days", policy.get("default_hot_window_days")
        ),
    }
