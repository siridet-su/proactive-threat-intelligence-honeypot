"""Fail-closed manifest and artifact checks for the corrected experiment.

The module defines gates for artifacts that do not yet exist. It does not load
Torch, train a model, open a final-test partition, or alter production.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Mapping

from production.prediction.next_behavior_contract import (
    MODEL_INPUT_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
    NextBehaviorContractError,
    require_valid_next_behavior_session,
)
from production.prediction.next_behavior_corpus import (
    NextBehaviorCorpusError,
    require_valid_corpus_receipt,
    require_valid_source_member_receipt,
)
from production.prediction.next_behavior_partitions import MEMBER_ROLES
from production.prediction.next_behavior_partitions import (
    PARTITION_SCHEMA_VERSION_V2,
)
from production.prediction.next_behavior_experiment_policy import (
    NextBehaviorExperimentPolicyError,
    experiment_policy_sha256,
    require_valid_experiment_policy,
)
from production.prediction.next_behavior_source_selection import (
    NextBehaviorSourceSelectionError,
    require_completed_source_selection,
)
from production.prediction.next_behavior_tensor import (
    NextBehaviorTensorError,
    require_valid_vocabulary,
    vocabulary_sha256,
)
from production.prediction.next_behavior_model import (
    NextBehaviorModelError,
    require_valid_model_spec,
)
from production.prediction.next_behavior_baseline import (
    NextBehaviorBaselineError,
    require_valid_baseline,
)
from production.prediction.next_behavior_calibration import (
    NextBehaviorCalibrationError,
    require_valid_calibration_mapping,
)
from production.utils.serialization import stable_id, stable_json

EXPERIMENT_MANIFEST_SCHEMA_VERSION = "next_behavior_experiment_manifest.v1"
EXPERIMENT_MANIFEST_SCHEMA_VERSION_V2 = "next_behavior_experiment_manifest.v2"
EXPERIMENT_MANIFEST_STATUSES = frozenset({"frozen_pre_test"})
REQUIRED_ARTIFACT_ROLES = frozenset(
    {
        "checkpoint",
        "preprocessing",
        "vocabulary",
        "partition_manifest",
        "label_policy",
        "trust_policy",
        "environment_lock",
        "baseline_artifact",
        "baseline_manifest",
        "corpus_receipt",
        "safe_payload",
        "classification_checkpoint",
        "source_member_receipts",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_MANIFEST_ID = re.compile(r"^nextbehaviorexperiment_[0-9a-f]{32}$")
_TOP_FIELDS = frozenset(
    {
        "schema_version",
        "manifest_id",
        "status",
        "target_contract_id",
        "input_schema_version",
        "code_commit",
        "corpus",
        "partitions",
        "policies",
        "model",
        "baseline",
        "calibration",
        "decision_freeze",
        "artifact_hashes",
    }
)
_CORPUS_FIELDS = frozenset(
    {
        "receipt_id",
        "receipt_sha256",
        "safe_payload_sha256",
        "accepted_historical_exclusion_sha256",
        "safe_session_count",
        "trusted_group_count",
        "source_member_count",
        "source_member_receipts_artifact_sha256",
    }
)
_PARTITIONS_FIELDS = frozenset(
    {"manifest_id", "manifest_sha256", "membership_sha256", "test_opened"}
)
_POLICY_FIELDS = frozenset(
    {
        "preprocessing_sha256",
        "vocabulary_sha256",
        "label_policy_sha256",
        "trust_policy_sha256",
        "environment_lock_sha256",
        "classification_checkpoint_sha256",
    }
)
_MODEL_FIELDS = frozenset(
    {
        "family",
        "model_id",
        "architecture_sha256",
        "parameter_count",
        "checkpoint_sha256",
        "state_dictionary_sha256",
        "training_seed",
        "training_membership_sha256",
        "selection_membership_sha256",
        "selected_on_partition",
        "deterministic_replay_verified",
    }
)
_BASELINE_FIELDS = frozenset(
    {
        "family",
        "model_id",
        "target_contract_id",
        "artifact_sha256",
        "manifest_sha256",
        "training_membership_sha256",
        "selection_membership_sha256",
        "role",
    }
)
_CALIBRATION_FIELDS = frozenset(
    {
        "status",
        "method",
        "mapping_sha256",
        "fit_partition_membership_sha256",
    }
)
_FREEZE_FIELDS = frozenset(
    {
        "selection_rule_sha256",
        "promotion_rule_sha256",
        "feature_rule_sha256",
        "seed_rule_sha256",
        "calibration_rule_sha256",
        "frozen_before_test",
    }
)

# The v2 manifest is additive.  V1 remains the historical seven-member
# contract above; these roles bind the corrected 13-member experiment without
# changing how an accepted v1 bundle is read.
_V2_ROLE_MEMBER_COUNTS = {
    "train": 4,
    "selection": 1,
    "calibration": 1,
    "test": 7,
}
_V2_BASELINE_FAMILIES = (
    "majority_terminal_prevalence",
    "first_order_phase_state_markov",
    "hard_backoff_vomm",
    "interpolated_vomm",
)
REQUIRED_ARTIFACT_ROLES_V2 = frozenset(
    {
        "source_selection_receipt",
        "source_member_receipts",
        "experiment_policy",
        "preprocessing",
        "vocabulary",
        "partition_manifest",
        "environment_lock",
        "label_policy",
        "trust_policy",
        "classification_checkpoint",
        "checkpoint",
        "model_spec",
        "calibration",
        "baseline_manifest",
        *{
            f"baseline_{family}"
            for family in _V2_BASELINE_FAMILIES
        },
        *{
            f"{role}_{suffix}"
            for role in MEMBER_ROLES
            for suffix in ("role_inventory", "corpus_receipt", "safe_payload")
        },
    }
)
_V2_TOP_FIELDS = frozenset(
    {
        "schema_version",
        "manifest_id",
        "status",
        "target_contract_id",
        "input_schema_version",
        "code_commit",
        "source_selection",
        "corpora",
        "partitions",
        "policies",
        "model",
        "baselines",
        "calibration",
        "decision_freeze",
        "artifact_hashes",
    }
)
_V2_SOURCE_FIELDS = frozenset(
    {
        "selection_id",
        "completed_receipt_sha256",
        "source_member_count",
        "source_member_receipts_sha256",
    }
)
_V2_CORPUS_FIELDS = frozenset(MEMBER_ROLES)
_V2_ROLE_CORPUS_FIELDS = frozenset(
    {
        "receipt_id",
        "receipt_sha256",
        "safe_payload_sha256",
        "role_inventory_sha256",
        "source_member_count",
        "safe_session_count",
    }
)
_V2_POLICY_FIELDS = frozenset(
    {
        "experiment_policy_artifact_sha256",
        "experiment_policy_sha256",
        "preprocessing_sha256",
        "vocabulary_artifact_sha256",
        "vocabulary_sha256",
        "label_policy_sha256",
        "trust_policy_sha256",
        "environment_lock_sha256",
        "classification_checkpoint_sha256",
    }
)
_V2_MODEL_FIELDS = frozenset(
    {
        "family",
        "model_id",
        "architecture_sha256",
        "parameter_count",
        "checkpoint_sha256",
        "model_spec_artifact_sha256",
        "model_spec_sha256",
        "state_dictionary_sha256",
        "training_seed",
        "training_membership_sha256",
        "selection_membership_sha256",
        "selected_on_partition",
        "deterministic_replay_verified",
    }
)
_V2_BASELINES_FIELDS = frozenset(
    {"manifest_sha256", "training_membership_sha256", "families"}
)
_V2_BASELINE_ENTRY_FIELDS = frozenset(
    {
        "model_id",
        "artifact_sha256",
        "training_membership_sha256",
        "selection_membership_sha256",
    }
)
_V2_CALIBRATION_FIELDS = frozenset(
    {
        "artifact_sha256",
        "status",
        "method",
        "mapping_sha256",
        "fit_partition_membership_sha256",
    }
)


class NextBehaviorExperimentError(ValueError):
    """Raised when a corrected-target experiment bundle is unsafe."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _is_sha(value: Any, *, allow_empty: bool = False) -> bool:
    text = _clean(value).lower()
    return bool((allow_empty and not text) or _SHA256.fullmatch(text))


def _unexpected(
    value: Mapping[str, Any],
    allowed: frozenset[str],
    path: str,
) -> List[str]:
    return [
        f"{path}.{key} is not defined by the manifest contract"
        for key in sorted(value)
        if key not in allowed
    ]


def _require_object(
    parent: Mapping[str, Any],
    field: str,
    allowed: frozenset[str],
    errors: List[str],
) -> Mapping[str, Any]:
    value = parent.get(field)
    if not isinstance(value, dict):
        errors.append(f"{field} must be an object")
        return {}
    errors.extend(_unexpected(value, allowed, field))
    return value


def _require_hash_fields(
    value: Mapping[str, Any],
    fields: tuple[str, ...],
    path: str,
    errors: List[str],
) -> None:
    for field in fields:
        if not _is_sha(value.get(field)):
            errors.append(f"{path}.{field} must be a SHA-256 digest")


def _validate_experiment_manifest_v2(value: Mapping[str, Any]) -> List[str]:
    """Validate the additive 13-member pre-test freeze contract."""

    errors = _unexpected(value, _V2_TOP_FIELDS, "$")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append(
            "target_contract_id must name the corrected phase-or-end target"
        )
    if value.get("input_schema_version") != MODEL_INPUT_SCHEMA_VERSION:
        errors.append(
            f"input_schema_version must be {MODEL_INPUT_SCHEMA_VERSION}"
        )
    if value.get("status") != "frozen_pre_test":
        errors.append("status must be frozen_pre_test")
    if not _SAFE_ID.fullmatch(_clean(value.get("code_commit"))):
        errors.append("code_commit is invalid")

    source = _require_object(
        value, "source_selection", _V2_SOURCE_FIELDS, errors
    )
    if not _SAFE_ID.fullmatch(_clean(source.get("selection_id"))):
        errors.append("source_selection.selection_id is invalid")
    _require_hash_fields(
        source,
        ("completed_receipt_sha256", "source_member_receipts_sha256"),
        "source_selection",
        errors,
    )
    if source.get("source_member_count") != 13:
        errors.append("source_selection.source_member_count must be 13")

    corpora = _require_object(value, "corpora", _V2_CORPUS_FIELDS, errors)
    for role in MEMBER_ROLES:
        role_corpus = corpora.get(role)
        path = f"corpora.{role}"
        if not isinstance(role_corpus, dict):
            errors.append(f"{path} must be an object")
            continue
        errors.extend(_unexpected(role_corpus, _V2_ROLE_CORPUS_FIELDS, path))
        if not _SAFE_ID.fullmatch(_clean(role_corpus.get("receipt_id"))):
            errors.append(f"{path}.receipt_id is invalid")
        _require_hash_fields(
            role_corpus,
            ("receipt_sha256", "safe_payload_sha256", "role_inventory_sha256"),
            path,
            errors,
        )
        if role_corpus.get("source_member_count") != _V2_ROLE_MEMBER_COUNTS[role]:
            errors.append(
                f"{path}.source_member_count must be "
                f"{_V2_ROLE_MEMBER_COUNTS[role]}"
            )
        safe_count = role_corpus.get("safe_session_count")
        if (
            isinstance(safe_count, bool)
            or not isinstance(safe_count, int)
            or safe_count < 1
        ):
            errors.append(f"{path}.safe_session_count must be positive")

    partitions = _require_object(
        value, "partitions", _PARTITIONS_FIELDS, errors
    )
    if not _SAFE_ID.fullmatch(_clean(partitions.get("manifest_id"))):
        errors.append("partitions.manifest_id is invalid")
    _require_hash_fields(
        partitions, ("manifest_sha256",), "partitions", errors
    )
    if partitions.get("test_opened") is not False:
        errors.append("frozen_pre_test manifest requires test_opened=false")
    memberships = partitions.get("membership_sha256")
    if not isinstance(memberships, dict) or set(memberships) != set(MEMBER_ROLES):
        errors.append(
            "partitions.membership_sha256 must define every experimental role"
        )
        memberships = {}
    else:
        for role in MEMBER_ROLES:
            if not _is_sha(memberships.get(role)):
                errors.append(
                    f"partitions.membership_sha256.{role} "
                    "must be a SHA-256 digest"
                )
        if len(set(memberships.values())) != len(MEMBER_ROLES):
            errors.append("partition role membership hashes must be distinct")

    policies = _require_object(value, "policies", _V2_POLICY_FIELDS, errors)
    _require_hash_fields(
        policies,
        tuple(sorted(_V2_POLICY_FIELDS)),
        "policies",
        errors,
    )

    model = _require_object(value, "model", _V2_MODEL_FIELDS, errors)
    if model.get("family") != "small_causal_transformer":
        errors.append("model.family must be small_causal_transformer")
    if not _SAFE_ID.fullmatch(_clean(model.get("model_id"))):
        errors.append("model.model_id is invalid")
    _require_hash_fields(
        model,
        (
            "architecture_sha256",
            "checkpoint_sha256",
            "model_spec_artifact_sha256",
            "model_spec_sha256",
            "state_dictionary_sha256",
            "training_membership_sha256",
            "selection_membership_sha256",
        ),
        "model",
        errors,
    )
    parameter_count = model.get("parameter_count")
    if (
        isinstance(parameter_count, bool)
        or not isinstance(parameter_count, int)
        or parameter_count < 1
    ):
        errors.append("model.parameter_count must be positive")
    training_seed = model.get("training_seed")
    if (
        isinstance(training_seed, bool)
        or not isinstance(training_seed, int)
        or training_seed < 0
    ):
        errors.append("model.training_seed must be a non-negative integer")
    if model.get("selected_on_partition") != "selection":
        errors.append("model.selected_on_partition must be selection")
    if model.get("deterministic_replay_verified") is not True:
        errors.append("model.deterministic_replay_verified must be true")
    if memberships:
        if model.get("training_membership_sha256") != memberships["train"]:
            errors.append("model training membership does not match train role")
        if model.get("selection_membership_sha256") != memberships["selection"]:
            errors.append(
                "model selection membership does not match selection role"
            )

    baselines = _require_object(
        value, "baselines", _V2_BASELINES_FIELDS, errors
    )
    if not _is_sha(baselines.get("manifest_sha256")):
        errors.append("baselines.manifest_sha256 must be a SHA-256 digest")
    if memberships and baselines.get(
        "training_membership_sha256"
    ) != memberships.get("train"):
        errors.append("baseline training membership does not match train role")
    baseline_entries = baselines.get("families")
    if (
        not isinstance(baseline_entries, dict)
        or set(baseline_entries) != set(_V2_BASELINE_FAMILIES)
    ):
        errors.append("baselines.families must define all four frozen baselines")
        baseline_entries = {}
    else:
        for family in _V2_BASELINE_FAMILIES:
            entry = baseline_entries[family]
            path = f"baselines.families.{family}"
            if not isinstance(entry, dict):
                errors.append(f"{path} must be an object")
                continue
            errors.extend(
                _unexpected(entry, _V2_BASELINE_ENTRY_FIELDS, path)
            )
            if not _SAFE_ID.fullmatch(_clean(entry.get("model_id"))):
                errors.append(f"{path}.model_id is invalid")
            _require_hash_fields(
                entry,
                (
                    "artifact_sha256",
                    "training_membership_sha256",
                    "selection_membership_sha256",
                ),
                path,
                errors,
            )
            if memberships and entry.get(
                "training_membership_sha256"
            ) != memberships.get("train"):
                errors.append(f"{path} training membership mismatch")
            if memberships and entry.get(
                "selection_membership_sha256"
            ) != memberships.get("selection"):
                errors.append(f"{path} selection membership mismatch")

    calibration = _require_object(
        value, "calibration", _V2_CALIBRATION_FIELDS, errors
    )
    if not _is_sha(calibration.get("artifact_sha256")):
        errors.append("calibration.artifact_sha256 must be a SHA-256 digest")
    calibration_status = _clean(calibration.get("status"))
    if calibration_status not in {"not_implemented", "valid"}:
        errors.append("calibration.status must be not_implemented or valid")
    if memberships and calibration.get(
        "fit_partition_membership_sha256"
    ) != memberships.get("calibration"):
        errors.append("calibration membership does not match calibration role")
    if calibration_status == "valid":
        if not _clean(calibration.get("method")):
            errors.append("calibration.method is required")
        if not _is_sha(calibration.get("mapping_sha256")):
            errors.append("calibration.mapping_sha256 must be a SHA-256 digest")
    elif _clean(calibration.get("method")) or _clean(
        calibration.get("mapping_sha256")
    ):
        errors.append("not_implemented calibration cannot contain a mapping")

    freeze = _require_object(
        value, "decision_freeze", _FREEZE_FIELDS, errors
    )
    _require_hash_fields(
        freeze,
        (
            "selection_rule_sha256",
            "promotion_rule_sha256",
            "feature_rule_sha256",
            "seed_rule_sha256",
            "calibration_rule_sha256",
        ),
        "decision_freeze",
        errors,
    )
    if freeze.get("frozen_before_test") is not True:
        errors.append("decision rules must be frozen before test access")

    artifact_hashes = value.get("artifact_hashes")
    if not isinstance(artifact_hashes, dict) or set(artifact_hashes) != set(
        REQUIRED_ARTIFACT_ROLES_V2
    ):
        errors.append(
            "artifact_hashes must define every required v2 artifact role"
        )
        artifact_hashes = {}
    else:
        for role in sorted(REQUIRED_ARTIFACT_ROLES_V2):
            if not _is_sha(artifact_hashes.get(role)):
                errors.append(
                    f"artifact_hashes.{role} must be a SHA-256 digest"
                )

    expected_bindings = {
        "source_selection_receipt": source.get("completed_receipt_sha256"),
        "source_member_receipts": source.get(
            "source_member_receipts_sha256"
        ),
        "experiment_policy": policies.get(
            "experiment_policy_artifact_sha256"
        ),
        "preprocessing": policies.get("preprocessing_sha256"),
        "vocabulary": policies.get("vocabulary_artifact_sha256"),
        "partition_manifest": partitions.get("manifest_sha256"),
        "environment_lock": policies.get("environment_lock_sha256"),
        "label_policy": policies.get("label_policy_sha256"),
        "trust_policy": policies.get("trust_policy_sha256"),
        "classification_checkpoint": policies.get(
            "classification_checkpoint_sha256"
        ),
        "checkpoint": model.get("checkpoint_sha256"),
        "model_spec": model.get("model_spec_artifact_sha256"),
        "calibration": calibration.get("artifact_sha256"),
        "baseline_manifest": baselines.get("manifest_sha256"),
    }
    for role in MEMBER_ROLES:
        role_corpus = corpora.get(role) if isinstance(corpora, dict) else None
        if isinstance(role_corpus, dict):
            expected_bindings.update(
                {
                    f"{role}_role_inventory": role_corpus.get(
                        "role_inventory_sha256"
                    ),
                    f"{role}_corpus_receipt": role_corpus.get(
                        "receipt_sha256"
                    ),
                    f"{role}_safe_payload": role_corpus.get(
                        "safe_payload_sha256"
                    ),
                }
            )
    for family in _V2_BASELINE_FAMILIES:
        entry = baseline_entries.get(family)
        if isinstance(entry, dict):
            expected_bindings[f"baseline_{family}"] = entry.get(
                "artifact_sha256"
            )
    for role, expected in expected_bindings.items():
        if artifact_hashes and artifact_hashes.get(role) != expected:
            errors.append(
                f"artifact_hashes.{role} contradicts its manifest field"
            )

    manifest_id = _clean(value.get("manifest_id"))
    if not _MANIFEST_ID.fullmatch(manifest_id):
        errors.append("manifest_id is invalid")
    else:
        identity_payload = deepcopy(value)
        identity_payload.pop("manifest_id", None)
        if stable_id("nextbehaviorexperiment", identity_payload) != manifest_id:
            errors.append("manifest_id does not match manifest content")
    return errors


def validate_experiment_manifest(value: Any) -> List[str]:
    """Return stable errors for a complete corrected-target freeze manifest."""

    if not isinstance(value, dict):
        return ["experiment manifest must be an object"]
    if value.get("schema_version") == EXPERIMENT_MANIFEST_SCHEMA_VERSION_V2:
        return _validate_experiment_manifest_v2(value)
    errors = _unexpected(value, _TOP_FIELDS, "$")
    if value.get("schema_version") != EXPERIMENT_MANIFEST_SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {EXPERIMENT_MANIFEST_SCHEMA_VERSION}"
        )
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append(
            "target_contract_id must name the corrected phase-or-end target"
        )
    if value.get("input_schema_version") != MODEL_INPUT_SCHEMA_VERSION:
        errors.append(
            f"input_schema_version must be {MODEL_INPUT_SCHEMA_VERSION}"
        )
    status = _clean(value.get("status"))
    if status not in EXPERIMENT_MANIFEST_STATUSES:
        errors.append("status is invalid")
    if not _SAFE_ID.fullmatch(_clean(value.get("code_commit"))):
        errors.append("code_commit is invalid")

    corpus = _require_object(value, "corpus", _CORPUS_FIELDS, errors)
    if not _SAFE_ID.fullmatch(_clean(corpus.get("receipt_id"))):
        errors.append("corpus.receipt_id is invalid")
    _require_hash_fields(
        corpus,
        (
            "receipt_sha256",
            "safe_payload_sha256",
            "accepted_historical_exclusion_sha256",
        ),
        "corpus",
        errors,
    )
    for field in ("safe_session_count", "trusted_group_count"):
        count = corpus.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            errors.append(f"corpus.{field} must be positive")
    if corpus.get("source_member_count") != 7:
        errors.append("corpus.source_member_count must be seven")
    if not _is_sha(corpus.get("source_member_receipts_artifact_sha256")):
        errors.append(
            "corpus.source_member_receipts_artifact_sha256 must be a SHA-256 digest"
        )

    partitions = _require_object(
        value,
        "partitions",
        _PARTITIONS_FIELDS,
        errors,
    )
    if not _SAFE_ID.fullmatch(_clean(partitions.get("manifest_id"))):
        errors.append("partitions.manifest_id is invalid")
    if type(partitions.get("test_opened")) is not bool:
        errors.append("partitions.test_opened must be boolean")
    if status == "frozen_pre_test" and partitions.get("test_opened") is not False:
        errors.append("frozen_pre_test manifest cannot have an opened test")
    if not _is_sha(partitions.get("manifest_sha256")):
        errors.append("partitions.manifest_sha256 must be a SHA-256 digest")
    membership = partitions.get("membership_sha256")
    if not isinstance(membership, dict) or set(membership) != set(MEMBER_ROLES):
        errors.append(
            "partitions.membership_sha256 must define every experimental role"
        )
        membership = {}
    else:
        for role in MEMBER_ROLES:
            if not _is_sha(membership.get(role)):
                errors.append(
                    f"partitions.membership_sha256.{role} must be a SHA-256 digest"
                )
        membership_values = [membership.get(role) for role in MEMBER_ROLES]
        if len(set(membership_values)) != len(membership_values):
            errors.append("partition role membership hashes must be distinct")

    policies = _require_object(value, "policies", _POLICY_FIELDS, errors)
    _require_hash_fields(
        policies,
        (
            "preprocessing_sha256",
            "vocabulary_sha256",
            "label_policy_sha256",
            "trust_policy_sha256",
            "environment_lock_sha256",
            "classification_checkpoint_sha256",
        ),
        "policies",
        errors,
    )

    model = _require_object(value, "model", _MODEL_FIELDS, errors)
    if model.get("family") != "small_causal_transformer":
        errors.append("model.family must be small_causal_transformer")
    for field in ("model_id",):
        if not _SAFE_ID.fullmatch(_clean(model.get(field))):
            errors.append(f"model.{field} is invalid")
    _require_hash_fields(
        model,
        (
            "architecture_sha256",
            "checkpoint_sha256",
            "state_dictionary_sha256",
            "training_membership_sha256",
            "selection_membership_sha256",
        ),
        "model",
        errors,
    )
    parameter_count = model.get("parameter_count")
    if (
        isinstance(parameter_count, bool)
        or not isinstance(parameter_count, int)
        or parameter_count < 1
    ):
        errors.append("model.parameter_count must be positive")
    training_seed = model.get("training_seed")
    if (
        isinstance(training_seed, bool)
        or not isinstance(training_seed, int)
        or training_seed < 0
    ):
        errors.append("model.training_seed must be a non-negative integer")
    if model.get("selected_on_partition") != "selection":
        errors.append("model.selected_on_partition must be selection")
    if model.get("deterministic_replay_verified") is not True:
        errors.append("model.deterministic_replay_verified must be true")
    if membership:
        if model.get("training_membership_sha256") != membership.get("train"):
            errors.append("model training membership does not match train role")
        if model.get("selection_membership_sha256") != membership.get("selection"):
            errors.append(
                "model selection membership does not match selection role"
            )

    baseline = _require_object(value, "baseline", _BASELINE_FIELDS, errors)
    if baseline.get("family") != "hard_backoff_vomm":
        errors.append("baseline.family must be hard_backoff_vomm")
    if baseline.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append("baseline must be rebuilt for the corrected target")
    if baseline.get("role") != "interpretable_disagreement_reference_only":
        errors.append("baseline.role is invalid")
    if not _SAFE_ID.fullmatch(_clean(baseline.get("model_id"))):
        errors.append("baseline.model_id is invalid")
    _require_hash_fields(
        baseline,
        (
            "artifact_sha256",
            "manifest_sha256",
            "training_membership_sha256",
            "selection_membership_sha256",
        ),
        "baseline",
        errors,
    )
    if membership:
        if baseline.get("training_membership_sha256") != membership.get("train"):
            errors.append("baseline training membership does not match train role")
        if baseline.get("selection_membership_sha256") != membership.get(
            "selection"
        ):
            errors.append(
                "baseline selection membership does not match selection role"
            )

    calibration = _require_object(
        value,
        "calibration",
        _CALIBRATION_FIELDS,
        errors,
    )
    calibration_status = _clean(calibration.get("status"))
    if calibration_status not in {"not_implemented", "valid"}:
        errors.append("calibration.status must be not_implemented or valid")
    if membership and calibration.get(
        "fit_partition_membership_sha256"
    ) != membership.get("calibration"):
        errors.append("calibration membership does not match calibration role")
    if calibration_status == "valid":
        if not _clean(calibration.get("method")):
            errors.append("calibration.method is required")
        if not _is_sha(calibration.get("mapping_sha256")):
            errors.append("calibration.mapping_sha256 must be a SHA-256 digest")
    elif _clean(calibration.get("method")) or _clean(
        calibration.get("mapping_sha256")
    ):
        errors.append("not_implemented calibration cannot contain a mapping")

    freeze = _require_object(
        value,
        "decision_freeze",
        _FREEZE_FIELDS,
        errors,
    )
    _require_hash_fields(
        freeze,
        (
            "selection_rule_sha256",
            "promotion_rule_sha256",
            "feature_rule_sha256",
            "seed_rule_sha256",
            "calibration_rule_sha256",
        ),
        "decision_freeze",
        errors,
    )
    if freeze.get("frozen_before_test") is not True:
        errors.append("decision rules must be frozen before test access")

    artifact_hashes = value.get("artifact_hashes")
    if not isinstance(artifact_hashes, dict) or set(artifact_hashes) != (
        set(REQUIRED_ARTIFACT_ROLES)
    ):
        errors.append("artifact_hashes must define every required artifact role")
        artifact_hashes = {}
    else:
        for role in sorted(REQUIRED_ARTIFACT_ROLES):
            if not _is_sha(artifact_hashes.get(role)):
                errors.append(f"artifact_hashes.{role} must be a SHA-256 digest")
    expected_bindings = {
        "checkpoint": model.get("checkpoint_sha256"),
        "preprocessing": policies.get("preprocessing_sha256"),
        "vocabulary": policies.get("vocabulary_sha256"),
        "partition_manifest": partitions.get("manifest_sha256"),
        "label_policy": policies.get("label_policy_sha256"),
        "trust_policy": policies.get("trust_policy_sha256"),
        "environment_lock": policies.get("environment_lock_sha256"),
        "classification_checkpoint": policies.get(
            "classification_checkpoint_sha256"
        ),
        "baseline_artifact": baseline.get("artifact_sha256"),
        "baseline_manifest": baseline.get("manifest_sha256"),
        "corpus_receipt": corpus.get("receipt_sha256"),
        "safe_payload": corpus.get("safe_payload_sha256"),
        "source_member_receipts": corpus.get(
            "source_member_receipts_artifact_sha256"
        ),
    }
    for role, expected in expected_bindings.items():
        if artifact_hashes and artifact_hashes.get(role) != expected:
            errors.append(f"artifact_hashes.{role} contradicts its manifest field")

    manifest_id = _clean(value.get("manifest_id"))
    if not _MANIFEST_ID.fullmatch(manifest_id):
        errors.append("manifest_id is invalid")
    else:
        identity_payload = deepcopy(value)
        identity_payload.pop("manifest_id", None)
        if stable_id("nextbehaviorexperiment", identity_payload) != manifest_id:
            errors.append("manifest_id does not match manifest content")
    return errors


def with_experiment_manifest_id(value: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a copy with a deterministic identity over every frozen field."""

    output = deepcopy(dict(value))
    output.pop("manifest_id", None)
    output["manifest_id"] = stable_id("nextbehaviorexperiment", output)
    return output


def require_valid_experiment_manifest(value: Any) -> Dict[str, Any]:
    errors = validate_experiment_manifest(value)
    if errors:
        raise NextBehaviorExperimentError("; ".join(errors))
    return deepcopy(value)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_json_artifact(
    verified: Mapping[str, Mapping[str, Any]],
    role: str,
) -> Any:
    path = Path(verified[role]["path"])
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NextBehaviorExperimentError(
            f"{role} artifact is not valid JSON"
        ) from exc


def _verify_v2_artifacts(
    validated: Mapping[str, Any],
    artifact_paths: Mapping[str, str | Path],
) -> Dict[str, Any]:
    """Verify a v2 bundle without treating copied hashes as provenance.

    Every file is byte-verified before JSON is parsed.  In particular, the
    final-role payload is never parsed by this pre-test gate; its bytes are
    sealed here and can only be opened by the purpose-scoped final evaluator.
    """

    if set(artifact_paths) != set(REQUIRED_ARTIFACT_ROLES_V2):
        raise NextBehaviorExperimentError(
            "artifact paths must define every required v2 artifact role"
        )
    expected = validated["artifact_hashes"]
    verified: Dict[str, Dict[str, Any]] = {}
    for role in sorted(REQUIRED_ARTIFACT_ROLES_V2):
        path = Path(artifact_paths[role])
        if not path.is_file():
            raise NextBehaviorExperimentError(f"{role} artifact is missing")
        actual_sha256 = _sha256_file(path)
        if actual_sha256 != expected[role]:
            raise NextBehaviorExperimentError(f"{role} artifact hash mismatch")
        verified[role] = {
            "path": str(path),
            "sha256": actual_sha256,
            "size_bytes": path.stat().st_size,
        }

    source_selection = _load_json_artifact(
        verified, "source_selection_receipt"
    )
    try:
        source_selection = require_completed_source_selection(source_selection)
    except (NextBehaviorSourceSelectionError, ValueError) as exc:
        raise NextBehaviorExperimentError(
            "source selection receipt is incomplete or invalid"
        ) from exc
    if (
        source_selection["selection_id"]
        != validated["source_selection"]["selection_id"]
        or len(source_selection["members"]) != 13
    ):
        raise NextBehaviorExperimentError(
            "source selection semantic binding mismatch"
        )
    selection_receipts = {
        item["filename"]: item
        for item in source_selection["verification"]["member_receipts"]
    }

    source_receipts = _load_json_artifact(verified, "source_member_receipts")
    if not isinstance(source_receipts, list) or len(source_receipts) != 13:
        raise NextBehaviorExperimentError(
            "source member receipts must contain exactly 13 entries"
        )
    chronological: Dict[int, Dict[str, Any]] = {}
    member_ids: set[str] = set()
    for item in source_receipts:
        try:
            receipt = require_valid_source_member_receipt(item)
        except NextBehaviorCorpusError as exc:
            raise NextBehaviorExperimentError(
                "source member receipt is invalid"
            ) from exc
        order = receipt["chronological_order"]
        if order in chronological or receipt["member_id"] in member_ids:
            raise NextBehaviorExperimentError(
                "source member receipts are duplicated"
            )
        chronological[order] = receipt
        member_ids.add(receipt["member_id"])
    if set(chronological) != set(range(1, 14)):
        raise NextBehaviorExperimentError(
            "source member chronology must contain positions one through 13"
        )
    for selected in source_selection["members"]:
        order = selected["chronological_order"]
        archive_receipt = selection_receipts[selected["filename"]]
        if chronological[order]["sha256"] != archive_receipt["sha256"]:
            raise NextBehaviorExperimentError(
                "source member receipt does not match completed selection"
            )

    policy = _load_json_artifact(verified, "experiment_policy")
    try:
        policy = require_valid_experiment_policy(policy)
    except NextBehaviorExperimentPolicyError as exc:
        raise NextBehaviorExperimentError(
            "experiment policy is semantically invalid"
        ) from exc
    if (
        experiment_policy_sha256(policy)
        != validated["policies"]["experiment_policy_sha256"]
    ):
        raise NextBehaviorExperimentError(
            "experiment policy semantic hash mismatch"
        )

    partition = _load_json_artifact(verified, "partition_manifest")
    roles = partition.get("roles") if isinstance(partition, dict) else None
    if (
        not isinstance(partition, dict)
        or partition.get("schema_version") != PARTITION_SCHEMA_VERSION_V2
        or partition.get("status") != "membership_frozen"
        or partition.get("manifest_id")
        != validated["partitions"]["manifest_id"]
        or partition.get("target_contract_id") != TARGET_CONTRACT_ID
        or not isinstance(roles, dict)
        or set(roles) != set(MEMBER_ROLES)
    ):
        raise NextBehaviorExperimentError(
            "partition manifest semantic binding mismatch"
        )
    role_member_ids: set[str] = set()
    for role in MEMBER_ROLES:
        role_value = roles[role]
        member_values = (
            role_value.get("source_member_ids")
            if isinstance(role_value, dict)
            else None
        )
        if (
            not isinstance(member_values, list)
            or len(member_values) != _V2_ROLE_MEMBER_COUNTS[role]
            or len(set(member_values)) != len(member_values)
            or role_value.get("source_member_count")
            != _V2_ROLE_MEMBER_COUNTS[role]
            or role_value.get("example_membership_sha256")
            != validated["partitions"]["membership_sha256"][role]
            or role_value.get("cohort")
            != ("final" if role == "test" else "development")
        ):
            raise NextBehaviorExperimentError(
                f"partition manifest {role} semantic binding mismatch"
            )
        if role_member_ids.intersection(member_values):
            raise NextBehaviorExperimentError(
                "partition source-member roles intersect"
            )
        role_member_ids.update(member_values)
    if role_member_ids != member_ids:
        raise NextBehaviorExperimentError(
            "partition source membership does not match source receipts"
        )
    proofs = partition.get("intersection_proofs")
    if not isinstance(proofs, dict):
        raise NextBehaviorExperimentError(
            "partition intersection proofs are missing"
        )
    for proof_group in ("roles", "cohorts"):
        group = proofs.get(proof_group)
        if (
            not isinstance(group, dict)
            or not group
            or any(
                not isinstance(item, dict) or item.get("all_empty") is not True
                for item in group.values()
            )
        ):
            raise NextBehaviorExperimentError(
                f"partition {proof_group} intersections are not empty"
            )

    preprocessing = _load_json_artifact(verified, "preprocessing")
    if (
        not isinstance(preprocessing, dict)
        or preprocessing.get("target_contract_id") != TARGET_CONTRACT_ID
        or preprocessing.get("input_schema_version")
        != MODEL_INPUT_SCHEMA_VERSION
    ):
        raise NextBehaviorExperimentError(
            "preprocessing semantic binding mismatch"
        )
    vocabulary = _load_json_artifact(verified, "vocabulary")
    try:
        vocabulary = require_valid_vocabulary(vocabulary)
    except NextBehaviorTensorError as exc:
        raise NextBehaviorExperimentError(
            "vocabulary semantic binding mismatch"
        ) from exc
    if (
        vocabulary["preprocessing_sha256"]
        != validated["policies"]["preprocessing_sha256"]
        or vocabulary_sha256(vocabulary)
        != validated["policies"]["vocabulary_sha256"]
        or vocabulary["training_membership_sha256"]
        != validated["partitions"]["membership_sha256"]["train"]
    ):
        raise NextBehaviorExperimentError(
            "vocabulary semantic binding mismatch"
        )

    model_spec = _load_json_artifact(verified, "model_spec")
    try:
        model_spec = require_valid_model_spec(model_spec)
    except NextBehaviorModelError as exc:
        raise NextBehaviorExperimentError(
            "model spec semantic binding mismatch"
        ) from exc
    if (
        model_spec.get("spec_id") != validated["model"]["model_id"]
        or model_spec.get("spec_sha256")
        != validated["model"]["model_spec_sha256"]
        or model_spec.get("architecture_sha256")
        != validated["model"]["architecture_sha256"]
    ):
        raise NextBehaviorExperimentError(
            "model spec semantic binding mismatch"
        )

    calibration = _load_json_artifact(verified, "calibration")
    try:
        calibration = require_valid_calibration_mapping(calibration)
    except NextBehaviorCalibrationError as exc:
        raise NextBehaviorExperimentError(
            "calibration semantic binding mismatch"
        ) from exc
    if (
        calibration.get("status") != validated["calibration"]["status"]
        or calibration.get("method") != validated["calibration"]["method"]
        or calibration.get("mapping_sha256")
        != validated["calibration"]["mapping_sha256"]
        or calibration.get("fit_partition_membership_sha256")
        != validated["partitions"]["membership_sha256"]["calibration"]
        or calibration.get("checkpoint_sha256")
        != validated["model"]["checkpoint_sha256"]
        or calibration.get("vocabulary_sha256")
        != validated["policies"]["vocabulary_sha256"]
        or calibration.get("preprocessing_sha256")
        != validated["policies"]["preprocessing_sha256"]
    ):
        raise NextBehaviorExperimentError(
            "calibration semantic binding mismatch"
        )

    baseline_manifest = _load_json_artifact(verified, "baseline_manifest")
    baseline_entries = (
        baseline_manifest.get("artifacts")
        if isinstance(baseline_manifest, dict)
        else None
    )
    if (
        not isinstance(baseline_manifest, dict)
        or baseline_manifest.get("target_contract_id") != TARGET_CONTRACT_ID
        or baseline_manifest.get("experiment_policy_sha256")
        != validated["policies"]["experiment_policy_sha256"]
        or baseline_manifest.get("training_membership_sha256")
        != validated["partitions"]["membership_sha256"]["train"]
        or baseline_manifest.get("selection_membership_sha256")
        != validated["partitions"]["membership_sha256"]["selection"]
        or not isinstance(baseline_entries, dict)
        or set(baseline_entries) != set(_V2_BASELINE_FAMILIES)
    ):
        raise NextBehaviorExperimentError(
            "baseline manifest semantic binding mismatch"
        )
    for family in _V2_BASELINE_FAMILIES:
        artifact = _load_json_artifact(verified, f"baseline_{family}")
        try:
            artifact = require_valid_baseline(artifact)
        except NextBehaviorBaselineError as exc:
            raise NextBehaviorExperimentError(
                f"baseline {family} artifact is invalid"
            ) from exc
        declared = validated["baselines"]["families"][family]
        manifest_entry = baseline_entries[family]
        if (
            artifact.get("family") != family
            or artifact.get("model_id") != declared["model_id"]
            or manifest_entry.get("model_id") != declared["model_id"]
            or manifest_entry.get("artifact_sha256")
            != declared["artifact_sha256"]
        ):
            raise NextBehaviorExperimentError(
                f"baseline {family} semantic binding mismatch"
            )

    for role in MEMBER_ROLES:
        inventory = _load_json_artifact(
            verified, f"{role}_role_inventory"
        )
        role_corpus = validated["corpora"][role]
        if (
            not isinstance(inventory, dict)
            or inventory.get("schema_version")
            != "next_behavior_role_inventory.v1"
            or inventory.get("status") != "role_membership_frozen"
            or inventory.get("target_contract_id") != TARGET_CONTRACT_ID
            or inventory.get("role") != role
            or inventory.get("source_member_count")
            != _V2_ROLE_MEMBER_COUNTS[role]
            or inventory.get("eligible_complete_session_count")
            != role_corpus["safe_session_count"]
            or inventory.get("partial_sessions_can_emit_terminal_target")
            is not False
        ):
            raise NextBehaviorExperimentError(
                f"{role} role inventory semantic binding mismatch"
            )
        corpus_receipt = _load_json_artifact(
            verified, f"{role}_corpus_receipt"
        )
        try:
            corpus_receipt = require_valid_corpus_receipt(corpus_receipt)
        except NextBehaviorCorpusError as exc:
            raise NextBehaviorExperimentError(
                f"{role} corpus receipt is invalid"
            ) from exc
        if (
            corpus_receipt.get("receipt_id") != role_corpus["receipt_id"]
            or corpus_receipt.get("safe_payload_sha256")
            != role_corpus["safe_payload_sha256"]
            or corpus_receipt.get("source_member_count")
            != role_corpus["source_member_count"]
            or corpus_receipt.get("safe_session_count")
            != role_corpus["safe_session_count"]
            or corpus_receipt.get("preprocessing_sha256")
            != validated["policies"]["preprocessing_sha256"]
            or corpus_receipt.get("label_policy_sha256")
            != validated["policies"]["label_policy_sha256"]
            or corpus_receipt.get("trust_policy_sha256")
            != validated["policies"]["trust_policy_sha256"]
            or corpus_receipt.get("classification_checkpoint_sha256")
            != validated["policies"]["classification_checkpoint_sha256"]
        ):
            raise NextBehaviorExperimentError(
                f"{role} corpus receipt semantic binding mismatch"
            )

    return {
        "status": "verified_pre_test",
        "manifest_id": validated["manifest_id"],
        "target_contract_id": validated["target_contract_id"],
        "test_opened": False,
        "artifacts": verified,
    }


def verify_experiment_artifacts_v2_pretest(
    manifest: Mapping[str, Any],
    artifact_paths: Mapping[str, str | Path],
) -> Dict[str, Any]:
    """Public purpose boundary for the v2 freeze before final-test access."""

    validated = require_valid_experiment_manifest(manifest)
    if validated.get("schema_version") != EXPERIMENT_MANIFEST_SCHEMA_VERSION_V2:
        raise NextBehaviorExperimentError(
            "pre-test v2 verification requires a v2 experiment manifest"
        )
    return _verify_v2_artifacts(validated, artifact_paths)


def verify_experiment_artifacts(
    manifest: Mapping[str, Any],
    artifact_paths: Mapping[str, str | Path],
) -> Dict[str, Any]:
    """Verify all exact bytes before any corrected-target inference."""

    validated = require_valid_experiment_manifest(manifest)
    if (
        validated.get("schema_version")
        == EXPERIMENT_MANIFEST_SCHEMA_VERSION_V2
    ):
        return _verify_v2_artifacts(validated, artifact_paths)
    if set(artifact_paths) != set(REQUIRED_ARTIFACT_ROLES):
        raise NextBehaviorExperimentError(
            "artifact paths must define every required artifact role"
        )
    expected = validated["artifact_hashes"]
    verified: Dict[str, Dict[str, Any]] = {}
    for role in sorted(REQUIRED_ARTIFACT_ROLES):
        path = Path(artifact_paths[role])
        if not path.is_file():
            raise NextBehaviorExperimentError(f"{role} artifact is missing")
        actual_sha256 = _sha256_file(path)
        if actual_sha256 != expected[role]:
            raise NextBehaviorExperimentError(f"{role} artifact hash mismatch")
        verified[role] = {
            "path": str(path),
            "sha256": actual_sha256,
            "size_bytes": path.stat().st_size,
        }

    corpus_receipt = _load_json_artifact(verified, "corpus_receipt")
    try:
        corpus_receipt = require_valid_corpus_receipt(corpus_receipt)
    except NextBehaviorCorpusError as exc:
        raise NextBehaviorExperimentError("corpus receipt is invalid") from exc
    if (
        not isinstance(corpus_receipt, dict)
        or corpus_receipt.get("receipt_id") != validated["corpus"]["receipt_id"]
        or corpus_receipt.get("safe_payload_sha256")
        != validated["corpus"]["safe_payload_sha256"]
        or corpus_receipt.get("preprocessing_sha256")
        != validated["policies"]["preprocessing_sha256"]
        or corpus_receipt.get("label_policy_sha256")
        != validated["policies"]["label_policy_sha256"]
        or corpus_receipt.get("trust_policy_sha256")
        != validated["policies"]["trust_policy_sha256"]
        or corpus_receipt.get("classification_checkpoint_sha256")
        != validated["policies"]["classification_checkpoint_sha256"]
        or corpus_receipt.get("safe_session_count")
        != validated["corpus"]["safe_session_count"]
        or corpus_receipt.get("source_member_count")
        != validated["corpus"]["source_member_count"]
        or corpus_receipt.get("source_member_receipts_artifact_sha256")
        != validated["corpus"]["source_member_receipts_artifact_sha256"]
        or (corpus_receipt.get("counts") or {}).get("safe_trusted_group_count")
        != validated["corpus"]["trusted_group_count"]
    ):
        raise NextBehaviorExperimentError(
            "corpus receipt semantic binding mismatch"
        )

    source_receipts = _load_json_artifact(verified, "source_member_receipts")
    if (
        not isinstance(source_receipts, list)
        or len(source_receipts) != validated["corpus"]["source_member_count"]
    ):
        raise NextBehaviorExperimentError(
            "source member receipts semantic binding mismatch"
        )
    source_member_ids: set[str] = set()
    chronological_members: Dict[int, str] = {}
    receipt_hashes: List[str] = []
    for receipt in source_receipts:
        try:
            validated_receipt = require_valid_source_member_receipt(receipt)
        except NextBehaviorCorpusError as exc:
            raise NextBehaviorExperimentError(
                "source member receipt is invalid"
            ) from exc
        source_member_ids.add(validated_receipt["member_id"])
        chronological_members[validated_receipt["chronological_order"]] = (
            validated_receipt["member_id"]
        )
        receipt_hashes.append(
            hashlib.sha256(
                json.dumps(
                    validated_receipt,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
        )
    if len(source_member_ids) != len(source_receipts):
        raise NextBehaviorExperimentError("source member receipts are duplicated")
    if set(chronological_members) != set(range(1, 8)):
        raise NextBehaviorExperimentError(
            "source member chronology must contain positions one through seven"
        )
    receipt_hash = hashlib.sha256(
        json.dumps(
            sorted(receipt_hashes),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    if receipt_hash != corpus_receipt["source_member_receipts_sha256"]:
        raise NextBehaviorExperimentError(
            "source member receipt aggregate hash mismatch"
        )

    safe_payload = _load_json_artifact(verified, "safe_payload")
    if (
        not isinstance(safe_payload, list)
        or len(safe_payload) != validated["corpus"]["safe_session_count"]
    ):
        raise NextBehaviorExperimentError("safe payload semantic binding mismatch")
    for index, session in enumerate(safe_payload):
        try:
            validated_session = require_valid_next_behavior_session(session)
        except NextBehaviorContractError as exc:
            raise NextBehaviorExperimentError(
                f"safe payload session {index} is invalid"
            ) from exc
        if validated_session["source_member_id"] not in source_member_ids:
            raise NextBehaviorExperimentError(
                "safe payload source member has no receipt"
            )
        for group in validated_session["observation_groups"]:
            for provenance in [
                *(group.get("label_provenance") or []),
                *(group.get("audit_only_labels") or []),
            ]:
                if provenance.get("policy_sha256") != validated["policies"][
                    "label_policy_sha256"
                ]:
                    raise NextBehaviorExperimentError(
                        "safe payload label policy binding mismatch"
                    )
                if provenance.get("trust_policy_sha256") != validated["policies"][
                    "trust_policy_sha256"
                ]:
                    raise NextBehaviorExperimentError(
                        "safe payload trust policy binding mismatch"
                    )
                if provenance.get("source") in {
                    "securebert",
                    "rule_model_agreement",
                } and provenance.get("checkpoint_sha256") != validated[
                    "policies"
                ]["classification_checkpoint_sha256"]:
                    raise NextBehaviorExperimentError(
                        "safe payload classification checkpoint binding mismatch"
                    )

    preprocessing = _load_json_artifact(verified, "preprocessing")
    if (
        not isinstance(preprocessing, dict)
        or preprocessing.get("target_contract_id") != TARGET_CONTRACT_ID
        or preprocessing.get("input_schema_version")
        != MODEL_INPUT_SCHEMA_VERSION
    ):
        raise NextBehaviorExperimentError(
            "preprocessing semantic binding mismatch"
        )

    vocabulary = _load_json_artifact(verified, "vocabulary")
    try:
        vocabulary = require_valid_vocabulary(vocabulary)
    except NextBehaviorTensorError as exc:
        raise NextBehaviorExperimentError(
            "vocabulary semantic binding mismatch"
        ) from exc
    if (
        vocabulary["preprocessing_sha256"]
        != validated["policies"]["preprocessing_sha256"]
        or vocabulary["training_membership_sha256"]
        != validated["partitions"]["membership_sha256"]["train"]
    ):
        raise NextBehaviorExperimentError("vocabulary semantic binding mismatch")

    partition_manifest = _load_json_artifact(verified, "partition_manifest")
    partition_roles = (
        partition_manifest.get("roles")
        if isinstance(partition_manifest, dict)
        else None
    )
    if (
        not isinstance(partition_manifest, dict)
        or partition_manifest.get("manifest_id")
        != validated["partitions"]["manifest_id"]
        or partition_manifest.get("target_contract_id") != TARGET_CONTRACT_ID
        or not isinstance(partition_roles, dict)
    ):
        raise NextBehaviorExperimentError(
            "partition manifest semantic binding mismatch"
        )
    for role in MEMBER_ROLES:
        role_value = partition_roles.get(role)
        if (
            not isinstance(role_value, dict)
            or role_value.get("example_membership_sha256")
            != validated["partitions"]["membership_sha256"][role]
        ):
            raise NextBehaviorExperimentError(
                f"partition manifest {role} membership mismatch"
            )
    expected_role_members = {
        "train": [chronological_members[index] for index in range(1, 5)],
        "selection": [chronological_members[5]],
        "calibration": [chronological_members[6]],
        "test": [chronological_members[7]],
    }
    for role, expected_members in expected_role_members.items():
        if partition_roles[role].get("source_member_ids") != expected_members:
            raise NextBehaviorExperimentError(
                f"partition manifest {role} source member chronology mismatch"
            )

    baseline_manifest = _load_json_artifact(verified, "baseline_manifest")
    if (
        not isinstance(baseline_manifest, dict)
        or baseline_manifest.get("target_contract_id") != TARGET_CONTRACT_ID
        or baseline_manifest.get("artifact_sha256")
        != validated["baseline"]["artifact_sha256"]
    ):
        raise NextBehaviorExperimentError(
            "baseline manifest semantic binding mismatch"
        )
    return {
        "status": "verified",
        "manifest_id": validated["manifest_id"],
        "target_contract_id": validated["target_contract_id"],
        "artifacts": verified,
    }
