"""Semantic validation for the frozen hardware-impact experiment protocol v2."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from typing import Any

from .batch import canonical_sha256
from .dataset import DatasetContractError


PROTOCOL_SCHEMA_VERSION = "hardware_impact_experiment_protocol.v2"


def validate_hardware_impact_protocol(document: Mapping[str, Any]) -> dict[str, Any]:
    """Validate invariants that JSON Schema alone cannot express."""

    if document.get("schema_version") != PROTOCOL_SCHEMA_VERSION:
        raise DatasetContractError("unexpected hardware-impact protocol version")
    claimed_hash = document.get("protocol_sha256")
    without_hash = dict(document)
    without_hash.pop("protocol_sha256", None)
    expected_hash = canonical_sha256(without_hash)
    if claimed_hash != expected_hash:
        raise DatasetContractError(
            f"protocol_sha256 does not match content; expected {expected_hash}"
        )

    target = document["labels_and_authority"]
    if target["hardware_primary_target"] != "primary_impact":
        raise DatasetContractError("hardware model must target primary_impact")
    if target["ttp_role"] != "metadata_and_fusion_evaluation_only":
        raise DatasetContractError("TTP labels must not be a hardware-model target")

    scenarios = document["scenario_design"]["scenarios"]
    scenario_ids = [scenario["scenario_id"] for scenario in scenarios]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise DatasetContractError("scenario IDs must be unique")

    impact_dispositions: dict[str, set[str]] = defaultdict(set)
    impact_treatments: dict[str, dict[str, set[tuple[str, int]]]] = defaultdict(
        lambda: defaultdict(set)
    )
    impact_scenario_counts: Counter[str] = Counter()
    for scenario in scenarios:
        impact = scenario["primary_impact"]
        disposition = scenario["scenario_disposition"]
        impact_dispositions[impact].add(disposition)
        impact_treatments[impact][disposition].add(
            (scenario["workload_family"], scenario["intensity"])
        )
        impact_scenario_counts[impact] += 1
        ttps = scenario["ground_truth_ttps"]
        if disposition == "malicious_simulation" and not ttps:
            raise DatasetContractError("malicious simulation requires one TTP label")
        if disposition != "malicious_simulation" and ttps:
            raise DatasetContractError("benign/neutral scenarios must not carry TTP labels")
    material_impacts = set(target["hardware_classes"]) - {"NO_MATERIAL_IMPACT"}
    for impact in sorted(material_impacts):
        dispositions = impact_dispositions[impact]
        if not {"benign_control", "malicious_simulation"}.issubset(dispositions):
            raise DatasetContractError(
                f"material impact {impact} requires benign and malicious scenarios"
            )
        shared_treatments = (
            impact_treatments[impact]["benign_control"]
            & impact_treatments[impact]["malicious_simulation"]
        )
        if not shared_treatments:
            raise DatasetContractError(
                f"material impact {impact} requires a matched benign/malicious treatment"
            )

    acquisition = document["acquisition"]
    repetitions = acquisition["repetitions_per_scenario"]
    wave_total = sum(wave["repetitions_per_scenario"] for wave in acquisition["waves"])
    if wave_total != repetitions:
        raise DatasetContractError(
            "wave repetitions must sum to repetitions_per_scenario"
        )
    final_waves = [wave for wave in acquisition["waves"] if wave["partition"] == "final_test"]
    observed_partitions = {wave["partition"] for wave in acquisition["waves"]}
    if observed_partitions != {"development_train", "calibration", "final_test"}:
        raise DatasetContractError("protocol requires development, calibration, and final waves")
    if len(final_waves) != 1 or final_waves[0]["locked_until_model_freeze"] is not True:
        raise DatasetContractError("exactly one locked final_test wave is required")
    minimum_wave_days = sum(wave["minimum_distinct_days"] for wave in acquisition["waves"])
    if minimum_wave_days < acquisition["minimum_collection_days"]:
        raise DatasetContractError("wave day minimums do not satisfy minimum_collection_days")

    features = document["features"]
    profiles = features["profiles"]
    profile_ids = [profile["profile_id"] for profile in profiles]
    if len(profile_ids) != len(set(profile_ids)):
        raise DatasetContractError("feature profile IDs must be unique")
    forbidden = set(features["forbidden_model_features"])
    for profile in profiles:
        names = profile["feature_names"]
        if len(names) != len(set(names)):
            raise DatasetContractError(
                f"feature profile contains duplicates: {profile['profile_id']}"
            )
        leaked = sorted(set(names) & forbidden)
        if leaked:
            raise DatasetContractError(
                f"feature profile contains forbidden features: {leaked}"
            )
    required_profiles = {"host_extended_v2", "target_augmented_v2"}
    if not required_profiles.issubset(profile_ids):
        raise DatasetContractError("host and target-augmented candidate profiles are required")
    by_profile = {profile["profile_id"]: set(profile["feature_names"]) for profile in profiles}
    if not by_profile["host_extended_v2"].issubset(by_profile["target_augmented_v2"]):
        raise DatasetContractError("target-augmented profile must include every host feature")
    target_additions = by_profile["target_augmented_v2"] - by_profile["host_extended_v2"]
    if not target_additions or any(not name.startswith("target_") for name in target_additions):
        raise DatasetContractError(
            "target-augmented additions must be non-empty target_* features"
        )

    model = document["model_protocol"]
    if model["target"] != "primary_impact" or model["class_weighting"] != "balanced":
        raise DatasetContractError("XGBoost v2 must use balanced primary-impact training")
    if model["hyperparameter_tuning"] is not False:
        raise DatasetContractError("protocol v2 forbids hyperparameter tuning")
    if document["leakage_controls"]["final_test_opened"] is not False:
        raise DatasetContractError("final test must remain unopened at protocol freeze")

    total_runs = repetitions * len(scenarios)
    partition_runs = {
        wave["partition"]: wave["repetitions_per_scenario"] * len(scenarios)
        for wave in acquisition["waves"]
    }
    return {
        "protocol_id": document["protocol_id"],
        "protocol_sha256": claimed_hash,
        "scenario_count": len(scenarios),
        "repetitions_per_scenario": repetitions,
        "planned_run_count": total_runs,
        "planned_sample_count": total_runs
        * sum(acquisition["phase_seconds"].values())
        // acquisition["sample_interval_seconds"],
        "partition_run_counts": partition_runs,
        "impact_scenario_counts": dict(sorted(impact_scenario_counts.items())),
        "feature_profile_counts": {
            profile["profile_id"]: len(profile["feature_names"])
            for profile in profiles
        },
        "final_test_opened": False,
    }
