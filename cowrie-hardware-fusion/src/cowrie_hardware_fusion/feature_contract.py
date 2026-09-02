"""Semantic validation for frozen XGBoost and TCN input profiles."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .batch import canonical_sha256
from .dataset import DatasetContractError, validate_derived_window_identity


CONTRACT_SCHEMA_VERSION = "model_feature_contract.v1"
REQUIRED_XGBOOST_PROFILES = {
    "go_agent_overlap_v1",
    "host_extended_v3",
    "target_augmented_v3",
}
REQUIRED_TCN_PROFILES = {"host_extended_v3", "target_augmented_v3"}
EXPECTED_PROFILE_METADATA = {
    "go_agent_overlap_v1": ("diagnostic_baseline", "current_go_agent_overlap"),
    "host_extended_v3": ("candidate", "extended_host_collector"),
    "target_augmented_v3": ("candidate", "target_process_or_cgroup_required"),
}


def _profiles_by_id(
    values: Any,
    *,
    expected_ids: set[str],
    label: str,
) -> dict[str, Mapping[str, Any]]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise DatasetContractError(f"{label} profiles must be an array")
    profiles: dict[str, Mapping[str, Any]] = {}
    for profile in values:
        if not isinstance(profile, Mapping):
            raise DatasetContractError(f"{label} profile must be an object")
        profile_id = profile.get("profile_id")
        if not isinstance(profile_id, str) or profile_id in profiles:
            raise DatasetContractError(f"{label} profile IDs are invalid or duplicated")
        names = profile.get("input_names")
        if (
            not isinstance(names, list)
            or any(not isinstance(name, str) for name in names)
            or len(names) != len(set(names))
        ):
            raise DatasetContractError(f"{label} profile inputs are invalid: {profile_id}")
        profiles[profile_id] = profile
    if set(profiles) != expected_ids:
        raise DatasetContractError(f"{label} profile set is not frozen")
    for profile_id, profile in profiles.items():
        expected = EXPECTED_PROFILE_METADATA[profile_id]
        observed = (profile.get("role"), profile.get("deployment_availability"))
        if observed != expected:
            raise DatasetContractError(f"{label} profile metadata is not frozen: {profile_id}")
    return profiles


def _is_subsequence(subset: Sequence[str], full: Sequence[str]) -> bool:
    positions = {name: index for index, name in enumerate(full)}
    try:
        indexes = [positions[name] for name in subset]
    except KeyError:
        return False
    return indexes == sorted(indexes)


def validate_model_feature_contract(
    document: Mapping[str, Any],
    representative_window: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind exact model profiles to one semantically verified builder-v2 window."""

    if document.get("schema_version") != CONTRACT_SCHEMA_VERSION:
        raise DatasetContractError("unsupported model feature contract")
    claimed_hash = document.get("contract_sha256")
    without_hash = dict(document)
    without_hash.pop("contract_sha256", None)
    if not isinstance(claimed_hash, str) or canonical_sha256(without_hash) != claimed_hash:
        raise DatasetContractError("model feature contract hash does not match")
    if document.get("experiment_protocol") != {
        "schema_version": "hardware_impact_experiment_protocol.v2",
        "protocol_id": "pi-hardware-impact-v2-20260902",
        "protocol_sha256": "8eb0786e8427f7fa685a8d137db62b1ecfff40a7897b65f742915477b9b2471d",
    }:
        raise DatasetContractError("model feature contract protocol binding is not frozen")

    validate_derived_window_identity(representative_window)
    binding = document["builder_binding"]
    xgboost = representative_window["xgboost"]
    tcn = representative_window["tcn"]
    observed_binding = {
        "builder_version": representative_window["provenance"]["builder_version"],
        "window_schema_version": representative_window["schema_version"],
        "feature_schema_version": xgboost["feature_schema_version"],
        "feature_count": len(xgboost["feature_order"]),
        "feature_order_sha256": xgboost["feature_order_sha256"],
        "channel_schema_version": tcn["channel_schema_version"],
        "channel_count": len(tcn["channel_order"]),
        "channel_order_sha256": tcn["channel_order_sha256"],
    }
    if binding != observed_binding:
        raise DatasetContractError("model feature contract does not bind this builder output")

    forbidden = set(document["forbidden_model_inputs"])
    xgb_profiles = _profiles_by_id(
        document["xgboost_profiles"],
        expected_ids=REQUIRED_XGBOOST_PROFILES,
        label="XGBoost",
    )
    generated_features = set(xgboost["features"])
    for profile_id, profile in xgb_profiles.items():
        names = profile["input_names"]
        if names != sorted(names):
            raise DatasetContractError(f"XGBoost profile order is not lexical: {profile_id}")
        if set(names) - generated_features:
            raise DatasetContractError(f"XGBoost profile has unavailable inputs: {profile_id}")
        if set(names) & forbidden:
            raise DatasetContractError(f"XGBoost profile contains forbidden inputs: {profile_id}")

    go_names = set(xgb_profiles["go_agent_overlap_v1"]["input_names"])
    host_names = set(xgb_profiles["host_extended_v3"]["input_names"])
    target_names = set(xgb_profiles["target_augmented_v3"]["input_names"])
    if not go_names < host_names < target_names:
        raise DatasetContractError("XGBoost profiles must be strict nested comparisons")
    target_additions = target_names - host_names
    if not target_additions or any(not name.startswith("target_") for name in target_additions):
        raise DatasetContractError("target XGBoost additions must all use target_ prefix")
    if "target_process_present_fraction" in target_names:
        raise DatasetContractError("target process presence is a forbidden simulator artifact")

    tcn_profiles = _profiles_by_id(
        document["tcn_profiles"],
        expected_ids=REQUIRED_TCN_PROFILES,
        label="TCN",
    )
    full_channel_order = tcn["channel_order"]
    for profile_id, profile in tcn_profiles.items():
        names = profile["input_names"]
        if not _is_subsequence(names, full_channel_order):
            raise DatasetContractError(f"TCN profile order is unavailable: {profile_id}")
        if set(names) & forbidden:
            raise DatasetContractError(f"TCN profile contains forbidden inputs: {profile_id}")
    host_channels = set(tcn_profiles["host_extended_v3"]["input_names"])
    target_channels = set(tcn_profiles["target_augmented_v3"]["input_names"])
    if not host_channels < target_channels:
        raise DatasetContractError("target TCN profile must strictly contain host channels")
    if any(
        not name.startswith("target_")
        for name in target_channels - host_channels
    ):
        raise DatasetContractError("target TCN additions must all use target_ prefix")
    if document["tcn_missingness_policy"] != {
        "sample_present_required": True,
        "channel_present_required": True,
        "zero_value_is_not_observed_zero": True,
    }:
        raise DatasetContractError("TCN missingness policy is not fail closed")

    claims = document["claim_control"]
    if claims != {
        "deployment_authority": "audit_only",
        "target_profile_requires_shadow_availability_test": True,
        "simulator_receipt_is_model_input": False,
        "final_test_opened": False,
    }:
        raise DatasetContractError("model feature claim control is not fail closed")

    return {
        "contract_id": document["contract_id"],
        "contract_sha256": claimed_hash,
        "feature_count": binding["feature_count"],
        "channel_count": binding["channel_count"],
        "xgboost_profile_counts": {
            profile_id: len(profile["input_names"])
            for profile_id, profile in xgb_profiles.items()
        },
        "tcn_profile_counts": {
            profile_id: len(profile["input_names"])
            for profile_id, profile in tcn_profiles.items()
        },
        "final_test_opened": False,
        "deployment_authority": "audit_only",
    }
