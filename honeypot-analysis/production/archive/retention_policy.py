"""Project-authored retention policy and target binding.

This module contains policy only.  It deliberately has no MongoDB write
operation.  A retention configuration is an explicit binding of a target,
database, and storage epoch; missing or ambiguous values fail closed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


RETENTION_POLICY_VERSION = "mongo_pi_retention_policy.v1"
RETENTION_CONFIG_VERSION = "mongo_pi_retention_config.v1"
POLICY_CLASSES = frozenset(
    {
        "ARCHIVE_AND_PURGE_ELIGIBLE",
        "ARCHIVE_ONLY",
        "HOT_OPERATIONAL",
        "LONG_TERM_METADATA",
        "RECOMPUTABLE_DERIVED",
        "MANUAL_REVIEW_ONLY",
        "NEVER_AUTOMATICALLY_PURGE",
    }
)
CAPACITY_STATES = ("NORMAL", "WARNING", "HIGH", "CRITICAL")


class RetentionPolicyError(ValueError):
    """Raised when a retention policy is incomplete or unsafe."""


def _text(value: Any, name: str, *, allow_empty: bool = False) -> str:
    result = str(value or "").strip()
    if not result and not allow_empty:
        raise RetentionPolicyError(f"{name} is required")
    if any(ord(char) < 0x20 for char in result):
        raise RetentionPolicyError(f"{name} contains a control character")
    return result


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise RetentionPolicyError(f"{name} must be a positive integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise RetentionPolicyError(f"{name} must be a positive integer") from exc
    if result <= 0:
        raise RetentionPolicyError(f"{name} must be a positive integer")
    return result


def _ratio(value: Any, name: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise RetentionPolicyError(f"{name} must be a ratio") from exc
    if not 0 < result < 1:
        raise RetentionPolicyError(f"{name} must be between zero and one")
    return result


def _string_list(value: Any, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise RetentionPolicyError(f"{name} must be a list of non-empty strings")
    return tuple(item.strip() for item in value)


@dataclass(frozen=True)
class TargetBinding:
    """Non-secret Mongo target identity used by every retention receipt."""

    target_name: str
    role: str
    project_id: str
    cluster_id: str
    cluster_name: str
    srv_hostname: str
    database: str
    storage_epoch: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "TargetBinding":
        if not isinstance(value, Mapping):
            raise RetentionPolicyError("target binding must be an object")
        target = cls(
            target_name=_text(value.get("target_name"), "target.target_name"),
            role=_text(value.get("role"), "target.role"),
            project_id=_text(value.get("project_id"), "target.project_id"),
            cluster_id=_text(value.get("cluster_id"), "target.cluster_id"),
            cluster_name=_text(value.get("cluster_name"), "target.cluster_name"),
            srv_hostname=_text(value.get("srv_hostname"), "target.srv_hostname").lower(),
            database=_text(value.get("database"), "target.database"),
            storage_epoch=_text(value.get("storage_epoch"), "target.storage_epoch"),
        )
        if not target.srv_hostname.endswith(".mongodb.net"):
            raise RetentionPolicyError("target.srv_hostname must be a mongodb.net hostname")
        if any(char in target.srv_hostname for char in ("@", "/", "?", "#")):
            raise RetentionPolicyError("target.srv_hostname contains unsafe characters")
        return target

    def as_dict(self) -> dict[str, str]:
        return {
            "target_name": self.target_name,
            "role": self.role,
            "project_id": self.project_id,
            "cluster_id": self.cluster_id,
            "cluster_name": self.cluster_name,
            "srv_hostname": self.srv_hostname,
            "database": self.database,
            "storage_epoch": self.storage_epoch,
        }

    def source_target(self, collection: str) -> dict[str, str]:
        result = self.as_dict()
        result["collection"] = collection
        return {
            key: result[key]
            for key in (
                "project_id",
                "cluster_id",
                "cluster_name",
                "srv_hostname",
                "database",
                "collection",
                "storage_epoch",
            )
        }


@dataclass(frozen=True)
class CollectionPolicy:
    collection: str
    classification: str
    purpose: str
    authority_state_role: str
    primary_time_field: str | None
    hot_window_days: int | None
    terminal_state_condition: str
    required_terminal_fields: tuple[str, ...]
    blocked_statuses: tuple[str, ...]
    dependencies: tuple[str, ...]
    archive_eligible: bool
    auto_archive_eligible: bool
    purge_eligible: bool
    auto_purge_eligible: bool
    manual_review_required: bool
    reconstructable: bool
    recommended_retention_basis: str
    rationale: str

    @classmethod
    def from_mapping(cls, collection: str, value: Mapping[str, Any]) -> "CollectionPolicy":
        if not isinstance(value, Mapping):
            raise RetentionPolicyError(f"policy for {collection} must be an object")
        name = _text(collection, "collection")
        classification = _text(value.get("classification"), f"{name}.classification")
        if classification not in POLICY_CLASSES:
            raise RetentionPolicyError(f"{name}.classification is not an allowed policy class")
        primary = value.get("primary_time_field")
        if primary is not None:
            primary = _text(primary, f"{name}.primary_time_field")
        window = value.get("hot_window_days")
        if window is not None:
            if isinstance(window, bool) or not isinstance(window, int) or window < 0:
                raise RetentionPolicyError(f"{name}.hot_window_days is invalid")
        booleans = {}
        for key in (
            "archive_eligible",
            "auto_archive_eligible",
            "purge_eligible",
            "auto_purge_eligible",
            "manual_review_required",
            "reconstructable",
        ):
            if not isinstance(value.get(key), bool):
                raise RetentionPolicyError(f"{name}.{key} must be boolean")
            booleans[key] = value[key]
        if classification in {"HOT_OPERATIONAL", "NEVER_AUTOMATICALLY_PURGE"} and booleans["auto_purge_eligible"]:
            raise RetentionPolicyError(f"{name} cannot auto-purge in class {classification}")
        if booleans["auto_purge_eligible"] and not booleans["purge_eligible"]:
            raise RetentionPolicyError(f"{name}.auto_purge_eligible requires purge_eligible")
        if booleans["auto_archive_eligible"] and not booleans["archive_eligible"]:
            raise RetentionPolicyError(f"{name}.auto_archive_eligible requires archive_eligible")
        if booleans["auto_archive_eligible"] or booleans["purge_eligible"]:
            if primary is None or window is None:
                raise RetentionPolicyError(
                    f"{name} automatic/archive purge eligibility requires a typed time field and hot window"
                )
            if not value.get("required_terminal_fields"):
                raise RetentionPolicyError(
                    f"{name} automatic/archive purge eligibility requires terminal-state fields"
                )
        return cls(
            collection=name,
            classification=classification,
            purpose=_text(value.get("purpose"), f"{name}.purpose"),
            authority_state_role=_text(
                value.get("authority_state_role"), f"{name}.authority_state_role"
            ),
            primary_time_field=primary,
            hot_window_days=window,
            terminal_state_condition=_text(
                value.get("terminal_state_condition"), f"{name}.terminal_state_condition"
            ),
            required_terminal_fields=_string_list(
                value.get("required_terminal_fields"), f"{name}.required_terminal_fields"
            ),
            blocked_statuses=_string_list(value.get("blocked_statuses"), f"{name}.blocked_statuses"),
            dependencies=_string_list(value.get("dependencies"), f"{name}.dependencies"),
            archive_eligible=booleans["archive_eligible"],
            auto_archive_eligible=booleans["auto_archive_eligible"],
            purge_eligible=booleans["purge_eligible"],
            auto_purge_eligible=booleans["auto_purge_eligible"],
            manual_review_required=booleans["manual_review_required"],
            reconstructable=booleans["reconstructable"],
            recommended_retention_basis=_text(
                value.get("recommended_retention_basis"),
                f"{name}.recommended_retention_basis",
            ),
            rationale=_text(value.get("rationale"), f"{name}.rationale"),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "collection": self.collection,
            "classification": self.classification,
            "purpose": self.purpose,
            "authority_state_role": self.authority_state_role,
            "primary_time_field": self.primary_time_field,
            "hot_window_days": self.hot_window_days,
            "terminal_state_condition": self.terminal_state_condition,
            "required_terminal_fields": list(self.required_terminal_fields),
            "blocked_statuses": list(self.blocked_statuses),
            "dependencies": list(self.dependencies),
            "archive_eligible": self.archive_eligible,
            "auto_archive_eligible": self.auto_archive_eligible,
            "purge_eligible": self.purge_eligible,
            "auto_purge_eligible": self.auto_purge_eligible,
            "manual_review_required": self.manual_review_required,
            "reconstructable": self.reconstructable,
            "recommended_retention_basis": self.recommended_retention_basis,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class CapacityPolicy:
    quota_bytes: int
    warning_ratio: float
    high_ratio: float
    critical_ratio: float
    recovery_target_ratio: float
    max_documents_per_cycle: int
    max_logical_bytes_per_cycle: int
    max_batches_per_run: int
    batch_size_documents: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CapacityPolicy":
        if not isinstance(value, Mapping):
            raise RetentionPolicyError("capacity policy must be an object")
        thresholds = value.get("thresholds")
        if not isinstance(thresholds, Mapping):
            raise RetentionPolicyError("capacity.thresholds is required")
        warning = _ratio(thresholds.get("warning"), "capacity.thresholds.warning")
        high = _ratio(thresholds.get("high"), "capacity.thresholds.high")
        critical = _ratio(thresholds.get("critical"), "capacity.thresholds.critical")
        if not warning < high < critical:
            raise RetentionPolicyError("capacity thresholds must be warning < high < critical")
        recovery = _ratio(value.get("recovery_target_ratio"), "capacity.recovery_target_ratio")
        if recovery >= warning:
            raise RetentionPolicyError("recovery target must be below warning threshold")
        return cls(
            quota_bytes=_positive_int(value.get("quota_bytes"), "capacity.quota_bytes"),
            warning_ratio=warning,
            high_ratio=high,
            critical_ratio=critical,
            recovery_target_ratio=recovery,
            max_documents_per_cycle=_positive_int(
                value.get("max_documents_per_cycle"), "capacity.max_documents_per_cycle"
            ),
            max_logical_bytes_per_cycle=_positive_int(
                value.get("max_logical_bytes_per_cycle"),
                "capacity.max_logical_bytes_per_cycle",
            ),
            max_batches_per_run=_positive_int(
                value.get("max_batches_per_run"), "capacity.max_batches_per_run"
            ),
            batch_size_documents=_positive_int(
                value.get("batch_size_documents"), "capacity.batch_size_documents"
            ),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "quota_bytes": self.quota_bytes,
            "thresholds": {
                "warning": self.warning_ratio,
                "high": self.high_ratio,
                "critical": self.critical_ratio,
            },
            "recovery_target_ratio": self.recovery_target_ratio,
            "max_documents_per_cycle": self.max_documents_per_cycle,
            "max_logical_bytes_per_cycle": self.max_logical_bytes_per_cycle,
            "max_batches_per_run": self.max_batches_per_run,
            "batch_size_documents": self.batch_size_documents,
        }


@dataclass(frozen=True)
class RetentionConfig:
    document: Mapping[str, Any]
    policy_id: str
    target: TargetBinding
    capacity: CapacityPolicy
    pi: Mapping[str, Any]
    secondary: Mapping[str, Any]
    automation: Mapping[str, Any]
    canonical_collection_policies: Mapping[str, CollectionPolicy]
    legacy_collection_policies: Mapping[str, CollectionPolicy]
    active_policy_scope: str
    canonical_collection_names: tuple[str, ...]

    @classmethod
    def from_mapping(cls, document: Mapping[str, Any]) -> "RetentionConfig":
        validate_retention_config(document)
        canonical = tuple(str(item) for item in document["canonical_collection_names"])
        canonical_policies = {
            name: CollectionPolicy.from_mapping(name, value)
            for name, value in (document.get("canonical_collections") or {}).items()
        }
        legacy_policies = {
            name: CollectionPolicy.from_mapping(name, value)
            for name, value in (document.get("legacy_collections") or {}).items()
        }
        return cls(
            document=document,
            policy_id=_text(document.get("policy_id"), "policy_id"),
            target=TargetBinding.from_mapping(document["target"]),
            capacity=CapacityPolicy.from_mapping(document["capacity"]),
            pi=dict(document["pi"]),
            secondary=dict(document["secondary"]),
            automation=dict(document["automation"]),
            canonical_collection_policies=canonical_policies,
            legacy_collection_policies=legacy_policies,
            active_policy_scope=_text(document.get("active_policy_scope"), "active_policy_scope"),
            canonical_collection_names=canonical,
        )

    @property
    def policy_sha256(self) -> str:
        return hashlib.sha256(
            json.dumps(self.document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    @property
    def collection_policies(self) -> Mapping[str, CollectionPolicy]:
        """Policies for the explicitly selected runtime scope."""

        if self.active_policy_scope == "canonical":
            return self.canonical_collection_policies
        if self.active_policy_scope == "legacy_target_a":
            return self.legacy_collection_policies
        return {}

    def policy_for(self, collection: str) -> CollectionPolicy | None:
        return self.collection_policies.get(collection)

    def policies_for_scope(self, scope: str) -> Mapping[str, CollectionPolicy]:
        if scope == "canonical":
            return self.canonical_collection_policies
        if scope == "legacy_target_a":
            return self.legacy_collection_policies
        raise RetentionPolicyError(f"unknown policy scope: {scope}")

    @property
    def automatic_archive(self) -> bool:
        return bool(self.automation.get("automatic_archive", False))

    @property
    def automatic_purge(self) -> bool:
        return bool(self.automation.get("automatic_purge", False))


def validate_retention_config(document: Any) -> None:
    if not isinstance(document, Mapping):
        raise RetentionPolicyError("retention configuration must be an object")
    if document.get("schema_version") != RETENTION_CONFIG_VERSION:
        raise RetentionPolicyError("unsupported retention configuration version")
    _text(document.get("policy_id"), "policy_id")
    active_scope = _text(document.get("active_policy_scope"), "active_policy_scope")
    if active_scope not in {"canonical", "legacy_target_a"}:
        raise RetentionPolicyError("active_policy_scope must be canonical or legacy_target_a")
    TargetBinding.from_mapping(document.get("target") or {})
    CapacityPolicy.from_mapping(document.get("capacity") or {})
    for key in ("pi", "secondary", "automation"):
        if not isinstance(document.get(key), Mapping):
            raise RetentionPolicyError(f"{key} configuration is required")
    pi = document["pi"]
    _text(pi.get("archive_root"), "pi.archive_root")
    if not Path(str(pi["archive_root"])).is_absolute():
        raise RetentionPolicyError("pi.archive_root must be absolute")
    _positive_int(pi.get("minimum_reserved_bytes"), "pi.minimum_reserved_bytes")
    _ratio(pi.get("max_used_ratio_after_archive"), "pi.max_used_ratio_after_archive")
    secondary = document["secondary"]
    backend = _text(secondary.get("backend"), "secondary.backend")
    if backend != "filesystem":
        raise RetentionPolicyError("only the filesystem secondary backend is implemented; configure another backend explicitly later")
    _text(secondary.get("root"), "secondary.root")
    if not Path(str(secondary["root"])).is_absolute():
        raise RetentionPolicyError("secondary.root must be absolute")
    _positive_int(secondary.get("minimum_reserved_bytes"), "secondary.minimum_reserved_bytes")
    _ratio(secondary.get("max_used_ratio_after_archive"), "secondary.max_used_ratio_after_archive")
    pi_root = Path(str(pi["archive_root"]))
    secondary_root = Path(str(secondary["root"]))
    if pi_root == secondary_root or pi_root.is_relative_to(secondary_root) or secondary_root.is_relative_to(pi_root):
        raise RetentionPolicyError("secondary root must be independent of the Pi archive root")
    automation = document["automation"]
    for key in ("automatic_archive", "automatic_purge"):
        if not isinstance(automation.get(key), bool):
            raise RetentionPolicyError(f"automation.{key} must be boolean")
    canonical = document.get("canonical_collection_names")
    if not isinstance(canonical, list) or not canonical or not all(isinstance(item, str) and item for item in canonical):
        raise RetentionPolicyError("canonical_collection_names must be a non-empty string list")
    if len(canonical) != len(set(canonical)):
        raise RetentionPolicyError("canonical_collection_names contains duplicates")
    for group in ("canonical_collections", "legacy_collections"):
        values = document.get(group)
        if not isinstance(values, Mapping) or not values:
            raise RetentionPolicyError(f"{group} is required")
        for name, policy in values.items():
            CollectionPolicy.from_mapping(str(name), policy)
    names = set(document["canonical_collections"]) | set(document["legacy_collections"])
    if set(canonical) != set(document["canonical_collections"]):
        raise RetentionPolicyError("canonical_collection_names must exactly match canonical_collections")
    if not names:
        raise RetentionPolicyError("at least one collection policy is required")


def load_retention_config(path: str | Path) -> RetentionConfig:
    selected = Path(path)
    try:
        document = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RetentionPolicyError("retention configuration is unreadable") from exc
    return RetentionConfig.from_mapping(document)


def capacity_state(used_ratio: float | None, policy: CapacityPolicy) -> str:
    if used_ratio is None:
        return "CRITICAL"
    ratio = float(used_ratio)
    if ratio >= policy.critical_ratio:
        return "CRITICAL"
    if ratio >= policy.high_ratio:
        return "HIGH"
    if ratio >= policy.warning_ratio:
        return "WARNING"
    return "NORMAL"


def capacity_state_with_hysteresis(
    used_ratio: float | None,
    policy: CapacityPolicy,
    *,
    previous_state: str | None = None,
) -> str:
    """Apply the configured recovery target when a prior action is known.

    The instantaneous threshold state remains observable, but a HIGH/CRITICAL
    run is not considered rearmed until it has returned to the lower recovery
    target.  This prevents threshold thrashing between adjacent runs.
    """

    current = capacity_state(used_ratio, policy)
    if previous_state not in {"HIGH", "CRITICAL"} or used_ratio is None:
        return current
    if float(used_ratio) > policy.recovery_target_ratio:
        return previous_state
    return current


def target_ratio_for_state(state: str, policy: CapacityPolicy) -> float | None:
    if state in {"HIGH", "CRITICAL"}:
        return policy.recovery_target_ratio
    return None


def required_reclaim_bytes(
    logical_bytes: int,
    quota_bytes: int,
    state: str,
    policy: CapacityPolicy,
) -> int:
    target = target_ratio_for_state(state, policy)
    if target is None:
        return 0
    return max(0, int(logical_bytes) - int(quota_bytes * target))


def lifecycle_query(policy: CollectionPolicy, *, cutoff: Any) -> dict[str, Any] | None:
    """Build a type-correct, age-plus-terminal-state query.

    A policy with no BSON date field or no explicit hot window cannot produce
    an automatic candidate.  That is intentional: age alone is not a purge
    authorization.
    """

    if not policy.archive_eligible or not policy.primary_time_field or policy.hot_window_days is None:
        return None
    clauses: list[dict[str, Any]] = [
        {
            policy.primary_time_field: {
                "$type": "date",
                "$lt": cutoff,
            }
        }
    ]
    clauses.extend({field: True} for field in policy.required_terminal_fields)
    if policy.blocked_statuses:
        clauses.append({"status": {"$nin": list(policy.blocked_statuses)}})
    return {"$and": clauses}


def lifecycle_document_is_safe(policy: CollectionPolicy, document: Mapping[str, Any]) -> bool:
    if not policy.archive_eligible or policy.classification in {"HOT_OPERATIONAL", "NEVER_AUTOMATICALLY_PURGE"}:
        return False
    if any(document.get(field) is not True for field in policy.required_terminal_fields):
        return False
    if document.get("status") in policy.blocked_statuses:
        return False
    return True


__all__ = [
    "CAPACITY_STATES",
    "POLICY_CLASSES",
    "RETENTION_CONFIG_VERSION",
    "RETENTION_POLICY_VERSION",
    "CapacityPolicy",
    "CollectionPolicy",
    "RetentionConfig",
    "RetentionPolicyError",
    "TargetBinding",
    "capacity_state",
    "capacity_state_with_hysteresis",
    "lifecycle_document_is_safe",
    "lifecycle_query",
    "load_retention_config",
    "required_reclaim_bytes",
    "target_ratio_for_state",
    "validate_retention_config",
]
