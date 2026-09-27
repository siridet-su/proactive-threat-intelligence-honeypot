"""Versioned, fail-closed experimental Model2 overlay runtime.

The installed, hash-pinned V5 model is loaded first as the source contract.
Only an independently pinned experimental overlay supplies new weights and
preprocessing. The old complete episode remains the canonical source row.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Mapping

from research.model2_v5_style_unified_production_native.runtime import (
    LABEL_ORDER, LoadedUnifiedModel, infer_shadow, load_model,
)

from model2_backend_only_projection import (  # noqa: E402
    PROJECTION_SHA256, SOURCE_SCHEMA_SHA256, ProjectionError,
    project_backend_only,
)


BASE_ARTIFACT_SHA256 = "104d4c77a3e1536b847561abb19fc7c0d6d7dc0111cd98d1ff2d9c9d74a2ed1a"
POC_MODEL_VERSION = "MODEL2_V5_BACKEND_SSH_ONLY_EXPERIMENTAL_POC_20260924_V1"
POC_STATUS = "EXPERIMENTAL_POC_SHADOW_MODEL_NOT_VALIDATED_FOR_FIELD"


class PocContractError(ValueError):
    """An experimental overlay or its source contract is not trustworthy."""


def _vector(value: Any, length: int, name: str, *, positive: bool = False) -> tuple[float, ...]:
    if not isinstance(value, list) or len(value) != length:
        raise PocContractError(f"{name}_dimension_invalid")
    try:
        result = tuple(float(item) for item in value)
    except (TypeError, ValueError) as exc:
        raise PocContractError(f"{name}_numeric_invalid") from exc
    if not all(math.isfinite(item) and (not positive or item > 0) for item in result):
        raise PocContractError(f"{name}_value_invalid")
    return result


def load_backend_poc(*, base_artifact_path: Path, feature_schema_path: Path,
                     poc_artifact_path: Path, expected_poc_sha256: str) -> LoadedUnifiedModel:
    base = load_model(base_artifact_path, feature_schema_path=feature_schema_path,
                      expected_model_sha256=BASE_ARTIFACT_SHA256)
    if len(expected_poc_sha256) != 64 or any(char not in "0123456789abcdef" for char in expected_poc_sha256):
        raise PocContractError("expected_poc_sha256_invalid")
    payload = poc_artifact_path.read_bytes()
    actual_sha = hashlib.sha256(payload).hexdigest()
    if actual_sha != expected_poc_sha256:
        raise PocContractError("poc_artifact_sha256_mismatch")
    try:
        overlay = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PocContractError("poc_artifact_unreadable") from exc
    if not isinstance(overlay, Mapping):
        raise PocContractError("poc_artifact_not_object")
    required = {
        "schema_version": "model2_backend_ssh_only_experimental_overlay.v1",
        "status": POC_STATUS,
        "model_version": POC_MODEL_VERSION,
        "authority": "NON_AUTHORITATIVE_SHADOW_ONLY",
        "architecture": "torch.nn.Linear(32,3)",
        "one_model": True,
        "one_inference_call": True,
        "independent_binary_heads": False,
        "output_order": list(LABEL_ORDER),
        "input_dim": 32,
        "threshold": 0.0,
        "threshold_tuned": False,
        "base_artifact_sha256": BASE_ARTIFACT_SHA256,
        "source_feature_schema_sha256": SOURCE_SCHEMA_SHA256,
        "input_projection_contract_sha256": PROJECTION_SHA256,
        "validation_claim": "NONE_POC_HISTORICAL_ONLY",
    }
    if any(overlay.get(key) != expected for key, expected in required.items()):
        raise PocContractError("poc_artifact_contract_mismatch")
    preprocessing = overlay.get("preprocessing")
    state = overlay.get("state_dict")
    if not isinstance(preprocessing, Mapping) or not isinstance(state, Mapping):
        raise PocContractError("poc_parameters_missing")
    if preprocessing.get("imputation") != "forbidden" or preprocessing.get("zero_fill") is not False:
        raise PocContractError("poc_imputation_forbidden")
    weights = state.get("weight")
    if not isinstance(weights, list) or len(weights) != 3:
        raise PocContractError("poc_weight_matrix_invalid")
    return dataclasses.replace(
        base, model_version=POC_MODEL_VERSION, model_sha256=actual_sha,
        mean=_vector(preprocessing.get("center"), 32, "center"),
        scale=_vector(preprocessing.get("scale"), 32, "scale", positive=True),
        block_scales=_vector(preprocessing.get("block_scales"), 32, "block_scales", positive=True),
        weight_matrix=tuple(_vector(head, 32, "weight") for head in weights),
        bias=_vector(state.get("bias"), 3, "bias"),
        artifact=overlay,
    )


def infer_backend_poc(row: Mapping[str, Any], model: LoadedUnifiedModel) -> dict[str, Any]:
    try:
        if model.model_version != POC_MODEL_VERSION or model.artifact.get("input_projection_contract_sha256") != PROJECTION_SHA256:
            raise PocContractError("poc_model_projection_contract_mismatch")
        projected = project_backend_only(row)
    except (PocContractError, ProjectionError) as exc:
        return {
            "schema_version": "model2_v5_style_unified_production_native_shadow_result.v1",
            "status": "UNAVAILABLE", "availability": "UNAVAILABLE",
            "authority": "NON_AUTHORITATIVE_SHADOW_ONLY",
            "model_version": model.model_version,
            "model_artifact_sha256": model.model_sha256,
            "input_projection_contract_sha256": PROJECTION_SHA256,
            "quality_status": "EXPERIMENTAL_POC_UNVALIDATED",
            "reason": str(exc),
            "outputs": {name: {"availability": "UNAVAILABLE", "decision": None, "raw_score": None}
                        for name in LABEL_ORDER},
        }
    result = infer_shadow(projected, model)
    result["input_projection_contract_sha256"] = PROJECTION_SHA256
    result["source_feature_contract_sha256"] = SOURCE_SCHEMA_SHA256
    result["quality_status"] = "EXPERIMENTAL_POC_UNVALIDATED"
    return result
