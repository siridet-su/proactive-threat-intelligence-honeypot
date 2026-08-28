"""Validate the behavioral-remediation contract ownership and lineage registry."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = "remediation_contract_lineage.v1"
DISPOSITIONS = {
    "readable_immutable_not_reinterpreted",
    "readable_immutable_not_newly_trusted",
    "readable_immutable",
    "readable_immutable_display_only",
    "readable_immutable_reduced_provenance",
    "readable_display_only_not_v3_inference_eligible",
    "readable_historical_model_only",
    "readable_immutable_not_revalidated_as_v4",
    "readable_legacy_non_authoritative",
}


def validate_remediation_contract_lineage(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["lineage registry must be an object"]
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    baseline = value.get("baseline")
    if not isinstance(baseline, Mapping):
        errors.append("baseline must be an object")
    else:
        for field, length in (("commit", 40), ("git_tree", 40), ("tracked_inventory_sha256", 64), ("baseline_fingerprint", 64)):
            text = str(baseline.get(field) or "").strip().lower()
            if len(text) != length or any(character not in "0123456789abcdef" for character in text):
                errors.append(f"baseline.{field} is invalid")
    contracts = value.get("contracts")
    if not isinstance(contracts, list) or not contracts:
        return errors + ["contracts must be a non-empty array"]
    families: set[str] = set()
    schema_owners: dict[str, str] = {}
    for index, item in enumerate(contracts):
        path = f"contracts[{index}]"
        if not isinstance(item, Mapping):
            errors.append(f"{path} must be an object")
            continue
        family = str(item.get("contract_family") or "").strip()
        if not family:
            errors.append(f"{path}.contract_family is required")
        elif family in families:
            errors.append(f"duplicate contract_family: {family}")
        families.add(family)
        for field in ("historical_schema", "planned_schema"):
            schema = str(item.get(field) or "").strip()
            if not schema:
                errors.append(f"{path}.{field} is required")
                continue
            owner = schema_owners.setdefault(schema, family)
            if owner != family:
                errors.append(f"ambiguous schema owner: {schema}")
        if item.get("historical_disposition") not in DISPOSITIONS:
            errors.append(f"{path}.historical_disposition is invalid")
        phase = item.get("planned_phase")
        if isinstance(phase, bool) or not isinstance(phase, int) or phase < 1:
            errors.append(f"{path}.planned_phase must be a positive integer")
        if not str(item.get("producer") or "").strip():
            errors.append(f"{path}.producer is required")
        consumers = item.get("consumers")
        if not isinstance(consumers, list) or not consumers or any(not str(value or "").strip() for value in consumers):
            errors.append(f"{path}.consumers must be a non-empty string array")
        elif len(consumers) != len(set(consumers)):
            errors.append(f"{path}.consumers must be unique")
    return errors


def load_and_validate(path: str | Path) -> dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    errors = validate_remediation_contract_lineage(document)
    if errors:
        raise ValueError("; ".join(errors))
    return document
