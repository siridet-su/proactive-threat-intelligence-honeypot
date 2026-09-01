"""Fail-closed contract validation for bounded workloads on an isolated backend.

This module intentionally does not execute containers or commands. It proves that a
reviewed specification, scenario catalog, and planned manifest agree before a separate
runtime adapter may be implemented and authorized.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .batch import canonical_sha256
from .dataset import DatasetContractError


WORKLOAD_SPEC_SCHEMA_VERSION = "bounded_workload_spec.v1"
PREFLIGHT_SCHEMA_VERSION = "bounded_workload_preflight_receipt.v1"


def _schema_validator(schema_dir: Path, filename: str) -> Draft202012Validator:
    schema = json.loads((schema_dir / filename).read_text(encoding="utf-8"))
    return Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def _validate(
    document: Mapping[str, Any], validator: Draft202012Validator, label: str
) -> None:
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if not errors:
        return
    error = errors[0]
    location = ".".join(str(component) for component in error.absolute_path) or "$"
    raise DatasetContractError(f"{label}:{location}: {error.message}")


def _scenario(catalog: Mapping[str, Any], scenario_id: str) -> Mapping[str, Any]:
    scenarios = catalog.get("scenarios")
    if not isinstance(scenarios, list):
        raise DatasetContractError("scenario catalog scenarios must be an array")
    matches = [
        item
        for item in scenarios
        if isinstance(item, Mapping) and item.get("scenario_id") == scenario_id
    ]
    if len(matches) != 1:
        raise DatasetContractError(
            f"scenario catalog must contain exactly one scenario_id={scenario_id}"
        )
    scenario = matches[0]
    required_fields = {
        "disposition",
        "safe_workload_family",
        "execution_boundary",
        "target_metric_scopes",
        "primary_impact",
        "ground_truth_ttps",
    }
    missing = sorted(required_fields - set(scenario))
    if missing:
        raise DatasetContractError(
            f"scenario catalog entry is missing fields: {','.join(missing)}"
        )
    return scenario


def validate_bounded_workload(
    manifest: Mapping[str, Any],
    specification: Mapping[str, Any],
    *,
    catalog_path: Path,
    schema_dir: Path,
) -> dict[str, Any]:
    """Return a content-bound preflight receipt without starting a workload."""

    _validate(
        manifest,
        _schema_validator(schema_dir, "experiment_run_manifest.v1.schema.json"),
        "manifest",
    )
    _validate(
        specification,
        _schema_validator(schema_dir, "bounded_workload_spec.v1.schema.json"),
        "workload specification",
    )
    if manifest["state"] != "planned":
        raise DatasetContractError("bounded workload preflight requires a planned manifest")
    try:
        catalog_bytes = catalog_path.read_bytes()
        catalog = json.loads(catalog_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise DatasetContractError("scenario catalog cannot be read") from exc
    if not isinstance(catalog, dict):
        raise DatasetContractError("scenario catalog must contain one JSON object")
    catalog_hash = sha256(catalog_bytes).hexdigest()
    if specification["scenario_catalog_sha256"] != catalog_hash:
        raise DatasetContractError("workload specification scenario catalog hash does not match")
    if catalog.get("schema_version") != manifest["workload"]["scenario_catalog_version"]:
        raise DatasetContractError("manifest scenario catalog version does not match catalog")

    scenario_id = specification["scenario_id"]
    scenario = _scenario(catalog, scenario_id)
    workload = manifest["workload"]
    labels = manifest["labels"]
    boundary = manifest["execution_boundary"]
    safety = manifest["safety"]
    runner = specification["runner"]
    limits = specification["limits"]
    timing = specification["timing"]

    catalog_safety = catalog.get("safety_policy")
    required_catalog_safety = {
        "actual_malware_allowed": False,
        "cryptocurrency_mining_allowed": False,
        "public_or_third_party_targets_allowed": False,
        "default_deny_egress": True,
        "hard_resource_limits_required": True,
        "watchdog_required": True,
        "pi_attacker_controlled_execution_allowed": False,
    }
    if not isinstance(catalog_safety, Mapping):
        raise DatasetContractError("scenario catalog safety policy is missing")
    for field, expected in required_catalog_safety.items():
        if catalog_safety.get(field) is not expected:
            raise DatasetContractError(f"scenario catalog safety_policy.{field} is invalid")

    if scenario_id != "benign_compute_control":
        raise DatasetContractError("v1 workload contract authorizes only benign_compute_control")
    if (
        scenario["disposition"] != "benign_control"
        or labels["scenario_disposition"] != "benign_control"
    ):
        raise DatasetContractError("bounded ordinary workload must be labeled benign_control")
    if workload["scenario_id"] != scenario_id:
        raise DatasetContractError("manifest scenario_id does not match workload specification")
    if workload["family"] != scenario["safe_workload_family"]:
        raise DatasetContractError("manifest workload family does not match scenario catalog")
    if workload["implementation_sha256"] != runner["implementation_sha256"]:
        raise DatasetContractError("manifest workload implementation hash does not match")
    if workload["intensity_percent"] != specification["parameters"]["intensity_percent"]:
        raise DatasetContractError("manifest workload intensity does not match specification")
    if workload["intensity_basis"] != "assigned_cpu_capacity":
        raise DatasetContractError("benign compute control requires assigned_cpu_capacity")

    calculated_intensity = limits["cpu_quota_millicores"] * 100 / limits[
        "cpu_capacity_millicores"
    ]
    if abs(calculated_intensity - workload["intensity_percent"]) > 1e-9:
        raise DatasetContractError("CPU quota does not equal declared intensity_percent")
    if manifest["timing"]["workload_seconds"] != timing["workload_seconds"]:
        raise DatasetContractError("manifest workload duration does not match specification")
    if safety["watchdog_timeout_seconds"] != timing["watchdog_timeout_seconds"]:
        raise DatasetContractError("manifest watchdog timeout does not match specification")
    if timing["watchdog_timeout_seconds"] < (
        timing["workload_seconds"] + timing["termination_grace_seconds"]
    ):
        raise DatasetContractError("watchdog cannot cover workload plus termination grace")

    if boundary["kind"] != scenario["execution_boundary"] or boundary["kind"] != "disposable_vm":
        raise DatasetContractError("benign compute control requires a disposable_vm boundary")
    if runner["kind"] != "oci_container_in_disposable_vm":
        raise DatasetContractError("unsupported bounded workload runner kind")
    if boundary["execution_observed"] is not True:
        raise DatasetContractError("bounded workload requires execution_observed=true")
    if boundary["backend_image_sha256"] != runner["image_sha256"]:
        raise DatasetContractError("manifest backend image hash does not match runner image")
    if boundary["network_policy_sha256"] != specification["security"][
        "network_policy_sha256"
    ]:
        raise DatasetContractError("manifest network policy hash does not match specification")
    required_scopes = set(scenario["target_metric_scopes"])
    if set(boundary["metric_scopes"]) != required_scopes:
        raise DatasetContractError("manifest metric scopes do not exactly match scenario catalog")

    if labels["primary_impact"] != scenario["primary_impact"]:
        raise DatasetContractError("manifest primary impact does not match scenario catalog")
    if labels["primary_impact"] not in labels["observed_impacts"]:
        raise DatasetContractError("primary impact must be present in observed impacts")
    if labels["ground_truth_ttps"] != scenario["ground_truth_ttps"] or labels[
        "ground_truth_ttps"
    ]:
        raise DatasetContractError("benign control cannot declare ground-truth TTPs")
    if manifest["collection"]["command_events_required"] is not False:
        raise DatasetContractError("ordinary compute control does not accept command events")

    required_safety = {
        "bounded_benign_workload": True,
        "actual_malware_used": False,
        "public_or_third_party_target_used": False,
        "default_deny_egress": True,
        "hard_resource_limits": True,
    }
    for field, expected in required_safety.items():
        if safety[field] is not expected:
            raise DatasetContractError(f"manifest safety.{field} must be {expected}")
    if safety["egress_enforcement_scope"] != "execution_boundary":
        raise DatasetContractError("egress must be enforced at the execution boundary")

    security = specification["security"]
    for field in ("read_only_rootfs", "cap_drop_all", "no_new_privileges"):
        if security[field] is not True:
            raise DatasetContractError(f"workload security.{field} must be true")
    if security["network_mode"] != "none":
        raise DatasetContractError("benign compute control requires network_mode=none")
    if specification["input_policy"] != {
        "attacker_controlled_input": False,
        "fixed_entrypoint_only": True,
        "raw_cowrie_command_allowed": False,
    }:
        raise DatasetContractError("workload input policy is not fail closed")

    policy_document = {
        "runner_kind": runner["kind"],
        "network_mode": security["network_mode"],
        "network_policy_sha256": security["network_policy_sha256"],
        "read_only_rootfs": security["read_only_rootfs"],
        "cap_drop_all": security["cap_drop_all"],
        "no_new_privileges": security["no_new_privileges"],
        "seccomp_profile_sha256": security["seccomp_profile_sha256"],
        "limits": deepcopy(limits),
        "timing": deepcopy(timing),
        "input_policy": deepcopy(specification["input_policy"]),
    }
    receipt: dict[str, Any] = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "receipt_id": "workload-preflight-v1-"
        + canonical_sha256(
            {
                "run_id": manifest["run_id"],
                "spec_id": specification["spec_id"],
            }
        )[:40],
        "run_id": manifest["run_id"],
        "spec_id": specification["spec_id"],
        "scenario_id": scenario_id,
        "contract_valid": True,
        "execution_authorized": False,
        "scenario_catalog_sha256": catalog_hash,
        "manifest_content_sha256": canonical_sha256(manifest),
        "specification_content_sha256": canonical_sha256(specification),
        "execution_policy_sha256": canonical_sha256(policy_document),
        "runner": {
            "kind": runner["kind"],
            "image_sha256": runner["image_sha256"],
            "implementation_sha256": runner["implementation_sha256"],
            "entrypoint_id": runner["entrypoint_id"],
        },
        "limits": deepcopy(limits),
    }
    receipt["receipt_sha256"] = canonical_sha256(receipt)
    _validate(
        receipt,
        _schema_validator(schema_dir, "bounded_workload_preflight_receipt.v1.schema.json"),
        "workload preflight receipt",
    )
    return receipt
