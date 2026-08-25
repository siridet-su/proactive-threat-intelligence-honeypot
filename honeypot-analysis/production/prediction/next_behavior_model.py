"""Frozen small causal Transformer for corrected next-behavior tensors.

PyTorch is an optional dependency.  Importing this module and validating model
specifications does not require it; constructing, saving, loading, or running a
model does.  The module deliberately contains no corpus access or training
entry point.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    TACTIC_VOCABULARY,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
)
from production.prediction.next_behavior_tensor import (
    TARGET_TENSOR_SCHEMA_VERSION,
    TENSOR_SCHEMA_VERSION,
    VOCABULARY_SCHEMA_VERSION,
    require_valid_vocabulary,
    vocabulary_sha256,
)
from production.utils.serialization import stable_id, stable_json

try:  # Optional in the production application's minimal dependency set.
    import torch as _torch
    from torch import nn as _nn
except ImportError:  # pragma: no cover - exercised by minimal installations.
    _torch = None
    _nn = None


MODEL_SPEC_SCHEMA_VERSION = "next_behavior_model_spec.v1"
CHECKPOINT_SCHEMA_VERSION = "next_behavior_model_checkpoint.v1"
CHECKPOINT_METADATA_SCHEMA_VERSION = "next_behavior_checkpoint_metadata.v1"
CHECKPOINT_RECEIPT_SCHEMA_VERSION = "next_behavior_checkpoint_receipt.v1"
MODEL_OUTPUT_SCHEMA_VERSION = "next_behavior_model_output.v1"
MODEL_FAMILY = "small_causal_transformer"

OUTPUT_TACTICS = tuple(sorted(TACTIC_VOCABULARY))

ARCHITECTURE = {
    "causal_layers": 1,
    "d_model": 16,
    "feedforward_dimension": 32,
    "attention_heads": 4,
    "dropout": 0.1,
    "maximum_sequence_length": 8,
    "activation": "gelu",
    "batch_first": True,
    "norm_first": False,
    "phase_readout": "last_unmasked_phase",
    "tactic_objective": "independent_multilabel_logits",
    "terminal_objective": "independent_binary_logit",
    "device": "cpu",
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_INPUT_ID = re.compile(r"^nextbehaviorinput_[0-9a-f]{32}$")
_MODEL_SPEC_FIELDS = frozenset(
    {
        "schema_version",
        "spec_id",
        "family",
        "target_contract_id",
        "tensor_schema_version",
        "target_tensor_schema_version",
        "vocabulary_schema_version",
        "vocabulary_id",
        "vocabulary_sha256",
        "preprocessing_sha256",
        "architecture",
        "architecture_sha256",
        "input_dimensions",
        "output",
        "spec_sha256",
    }
)
_INPUT_DIMENSION_FIELDS = frozenset(
    {
        "maximum_sequence_length",
        "phase_tactic_count",
        "phase_technique_count",
        "phase_source_count",
        "phase_confidence_count",
        "phase_agreement_count",
        "repetition_category_count",
        "elapsed_time_category_count",
        "audit_count_category_count",
        "login_outcome_category_count",
        "command_count_category_count",
        "session_age_category_count",
        "confirmed_transfer_category_count",
    }
)
_FIXED_INPUT_DIMENSIONS = {
    "maximum_sequence_length": 8,
    "phase_tactic_count": 14,
    "phase_source_count": 3,
    "phase_confidence_count": 4,
    "phase_agreement_count": 6,
    "repetition_category_count": 4,
    "elapsed_time_category_count": 5,
    "audit_count_category_count": 4,
    "login_outcome_category_count": 3,
    "command_count_category_count": 5,
    "session_age_category_count": 5,
    "confirmed_transfer_category_count": 2,
}
_OUTPUT_FIELDS = frozenset(
    {
        "tactics",
        "tactic_logit_count",
        "terminal_logit_count",
        "terminal_label",
        "score_semantics",
    }
)
_TENSOR_FIELDS = frozenset(
    {
        "schema_version",
        "target_contract_id",
        "vocabulary_id",
        "vocabulary_sha256",
        "preprocessing_sha256",
        "source_input_hash",
        "sequence_length",
        "maximum_sequence_length",
        "attention_mask",
        "phase_tactic_multi_hot",
        "phase_technique_multi_hot",
        "phase_source_multi_hot",
        "phase_confidence_multi_hot",
        "phase_agreement_multi_hot",
        "phase_repetition_index",
        "phase_elapsed_time_index",
        "phase_audit_count_index",
        "context_login_outcome_index",
        "context_command_count_index",
        "context_session_age_index",
        "context_confirmed_transfer",
        "tensor_hash",
    }
)
_CHECKPOINT_FIELDS = frozenset(
    {"schema_version", "model_spec", "metadata", "state_dict"}
)
_CHECKPOINT_METADATA_FIELDS = frozenset(
    {
        "schema_version",
        "model_spec_sha256",
        "architecture_sha256",
        "vocabulary_sha256",
        "preprocessing_sha256",
        "state_dictionary_sha256",
        "parameter_count",
        "initialization_seed",
        "saved_device",
        "torch_version",
    }
)


class NextBehaviorModelError(ValueError):
    """Raised when a model spec, tensor, or optional dependency is invalid."""


class NextBehaviorCheckpointError(NextBehaviorModelError):
    """Raised when a checkpoint cannot be verified exactly."""


def torch_available() -> bool:
    """Return whether the optional PyTorch dependency imported successfully."""

    return _torch is not None


def _require_torch() -> Any:
    if _torch is None:
        raise NextBehaviorModelError(
            "PyTorch is required for next-behavior model construction and inference"
        )
    return _torch


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256.fullmatch(value))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _without(value: Mapping[str, Any], *fields: str) -> Dict[str, Any]:
    result = deepcopy(dict(value))
    for field in fields:
        result.pop(field, None)
    return result


def _architecture_identity(spec: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "family": spec.get("family"),
        "architecture": deepcopy(spec.get("architecture")),
        "input_dimensions": deepcopy(spec.get("input_dimensions")),
        "output": deepcopy(spec.get("output")),
    }


def build_model_spec(vocabulary: Mapping[str, Any]) -> Dict[str, Any]:
    """Bind the fixed architecture to one validated tensor vocabulary."""

    vocab = require_valid_vocabulary(vocabulary)
    missing_outputs = sorted(set(OUTPUT_TACTICS) - set(vocab["tactics"]))
    if missing_outputs:
        raise NextBehaviorModelError(
            "vocabulary does not contain every frozen output tactic"
        )
    spec: Dict[str, Any] = {
        "schema_version": MODEL_SPEC_SCHEMA_VERSION,
        "family": MODEL_FAMILY,
        "target_contract_id": TARGET_CONTRACT_ID,
        "tensor_schema_version": TENSOR_SCHEMA_VERSION,
        "target_tensor_schema_version": TARGET_TENSOR_SCHEMA_VERSION,
        "vocabulary_schema_version": VOCABULARY_SCHEMA_VERSION,
        "vocabulary_id": vocab["vocabulary_id"],
        "vocabulary_sha256": vocabulary_sha256(vocab),
        "preprocessing_sha256": vocab["preprocessing_sha256"],
        "architecture": deepcopy(ARCHITECTURE),
        "input_dimensions": {
            "maximum_sequence_length": vocab["maximum_sequence_length"],
            "phase_tactic_count": len(vocab["tactics"]),
            "phase_technique_count": len(vocab["techniques"]),
            "phase_source_count": len(vocab["label_sources"]),
            "phase_confidence_count": len(vocab["confidence_buckets"]),
            "phase_agreement_count": len(vocab["agreement_statuses"]),
            "repetition_category_count": len(vocab["repetition_buckets"]),
            "elapsed_time_category_count": len(vocab["elapsed_time_buckets"]),
            "audit_count_category_count": len(vocab["audit_count_buckets"]),
            "login_outcome_category_count": len(vocab["login_outcomes"]),
            "command_count_category_count": len(vocab["command_count_buckets"]),
            "session_age_category_count": len(vocab["session_age_buckets"]),
            "confirmed_transfer_category_count": 2,
        },
        "output": {
            "tactics": list(OUTPUT_TACTICS),
            "tactic_logit_count": len(OUTPUT_TACTICS),
            "terminal_logit_count": 1,
            "terminal_label": vocab["terminal_outcome"],
            "score_semantics": "raw_uncalibrated_logits",
        },
    }
    spec["architecture_sha256"] = _sha256_json(_architecture_identity(spec))
    spec["spec_sha256"] = _sha256_json(
        _without(spec, "spec_id", "spec_sha256")
    )
    spec["spec_id"] = stable_id(
        "nextbehaviormodelspec",
        _without(spec, "spec_id"),
    )
    return require_valid_model_spec(spec)


def require_valid_model_spec(value: Any) -> Dict[str, Any]:
    """Validate a model specification without importing or constructing Torch."""

    if not isinstance(value, dict):
        raise NextBehaviorModelError("model spec must be an object")
    unexpected = sorted(set(value) - _MODEL_SPEC_FIELDS)
    missing = sorted(_MODEL_SPEC_FIELDS - set(value))
    errors = [f"model spec field is not defined: {field}" for field in unexpected]
    errors.extend(f"model spec field is missing: {field}" for field in missing)
    if value.get("schema_version") != MODEL_SPEC_SCHEMA_VERSION:
        errors.append(f"schema_version must be {MODEL_SPEC_SCHEMA_VERSION}")
    if value.get("family") != MODEL_FAMILY:
        errors.append(f"family must be {MODEL_FAMILY}")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append("target_contract_id is invalid")
    if value.get("tensor_schema_version") != TENSOR_SCHEMA_VERSION:
        errors.append("tensor_schema_version is invalid")
    if value.get("target_tensor_schema_version") != TARGET_TENSOR_SCHEMA_VERSION:
        errors.append("target_tensor_schema_version is invalid")
    if value.get("vocabulary_schema_version") != VOCABULARY_SCHEMA_VERSION:
        errors.append("vocabulary_schema_version is invalid")
    if not isinstance(value.get("vocabulary_id"), str) or not value.get(
        "vocabulary_id"
    ):
        errors.append("vocabulary_id is invalid")
    for field in (
        "vocabulary_sha256",
        "preprocessing_sha256",
        "architecture_sha256",
        "spec_sha256",
    ):
        if not _is_sha256(value.get(field)):
            errors.append(f"{field} must be a SHA-256 digest")

    if value.get("architecture") != ARCHITECTURE:
        errors.append("architecture does not match the frozen architecture")

    dimensions = value.get("input_dimensions")
    if not isinstance(dimensions, dict):
        errors.append("input_dimensions must be an object")
        dimensions = {}
    else:
        if set(dimensions) != _INPUT_DIMENSION_FIELDS:
            errors.append("input_dimensions fields do not match the contract")
    for field in _INPUT_DIMENSION_FIELDS:
        count = dimensions.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            errors.append(f"input_dimensions.{field} must be positive")
    for field, expected in _FIXED_INPUT_DIMENSIONS.items():
        if dimensions.get(field) != expected:
            errors.append(
                f"input_dimensions.{field} must be {expected}"
            )
    technique_count = dimensions.get("phase_technique_count")
    if isinstance(technique_count, int) and technique_count > 100_000:
        errors.append("phase_technique_count exceeds the safety limit")

    output = value.get("output")
    if not isinstance(output, dict):
        errors.append("output must be an object")
        output = {}
    else:
        if set(output) != _OUTPUT_FIELDS:
            errors.append("output fields do not match the contract")
    expected_output = {
        "tactics": list(OUTPUT_TACTICS),
        "tactic_logit_count": len(OUTPUT_TACTICS),
        "terminal_logit_count": 1,
        "score_semantics": "raw_uncalibrated_logits",
    }
    for field, expected in expected_output.items():
        if output.get(field) != expected:
            errors.append(f"output.{field} does not match the frozen output")
    if output.get("terminal_label") != TERMINAL_OUTCOME:
        errors.append("output.terminal_label is invalid")

    if not errors:
        expected_architecture_hash = _sha256_json(_architecture_identity(value))
        if value["architecture_sha256"] != expected_architecture_hash:
            errors.append("architecture_sha256 does not match model structure")
        expected_spec_hash = _sha256_json(
            _without(value, "spec_id", "spec_sha256")
        )
        if value["spec_sha256"] != expected_spec_hash:
            errors.append("spec_sha256 does not match model spec")
        expected_spec_id = stable_id(
            "nextbehaviormodelspec",
            _without(value, "spec_id"),
        )
        if value.get("spec_id") != expected_spec_id:
            errors.append("spec_id does not match model spec")
    if errors:
        raise NextBehaviorModelError("; ".join(errors))
    return deepcopy(value)


def _module_spec(model: Any) -> Dict[str, Any]:
    spec = getattr(model, "model_spec", None)
    if not isinstance(spec, dict):
        raise NextBehaviorModelError("model is missing its frozen model spec")
    return require_valid_model_spec(spec)


if _nn is not None:

    class NextBehaviorCausalTransformer(_nn.Module):
        """One-layer CPU causal Transformer with independent output heads."""

        def __init__(self, spec: Mapping[str, Any], *, seed: int = 0) -> None:
            super().__init__()
            validated = require_valid_model_spec(spec)
            if (
                isinstance(seed, bool)
                or not isinstance(seed, int)
                or not 0 <= seed <= (2**63 - 1)
            ):
                raise NextBehaviorModelError(
                    "initialization seed must be a non-negative integer"
                )
            _torch.manual_seed(seed)
            _torch.use_deterministic_algorithms(True)
            self.model_spec = validated
            self.initialization_seed = seed
            dimensions = validated["input_dimensions"]
            dense_width = sum(
                dimensions[field]
                for field in (
                    "phase_tactic_count",
                    "phase_technique_count",
                    "phase_source_count",
                    "phase_confidence_count",
                    "phase_agreement_count",
                )
            )
            d_model = ARCHITECTURE["d_model"]
            self.phase_projection = _nn.Linear(
                dense_width, d_model, bias=False
            )
            self.repetition_embedding = _nn.Embedding(
                dimensions["repetition_category_count"] + 1,
                d_model,
                padding_idx=0,
            )
            self.elapsed_embedding = _nn.Embedding(
                dimensions["elapsed_time_category_count"] + 1,
                d_model,
                padding_idx=0,
            )
            self.audit_embedding = _nn.Embedding(
                dimensions["audit_count_category_count"] + 1,
                d_model,
                padding_idx=0,
            )
            self.login_embedding = _nn.Embedding(
                dimensions["login_outcome_category_count"] + 1, d_model
            )
            self.command_count_embedding = _nn.Embedding(
                dimensions["command_count_category_count"] + 1, d_model
            )
            self.session_age_embedding = _nn.Embedding(
                dimensions["session_age_category_count"] + 1, d_model
            )
            self.transfer_embedding = _nn.Embedding(2, d_model)
            self.position_embedding = _nn.Embedding(
                ARCHITECTURE["maximum_sequence_length"], d_model
            )
            layer = _nn.TransformerEncoderLayer(
                d_model=d_model,
                nhead=ARCHITECTURE["attention_heads"],
                dim_feedforward=ARCHITECTURE["feedforward_dimension"],
                dropout=ARCHITECTURE["dropout"],
                activation=ARCHITECTURE["activation"],
                batch_first=True,
                norm_first=False,
            )
            self.encoder = _nn.TransformerEncoder(
                layer,
                num_layers=ARCHITECTURE["causal_layers"],
                enable_nested_tensor=False,
            )
            self.tactic_head = _nn.Linear(d_model, len(OUTPUT_TACTICS))
            self.terminal_head = _nn.Linear(d_model, 1)
            self.to(_torch.device("cpu"))

        @staticmethod
        def _causal_mask(length: int) -> Any:
            return _torch.triu(
                _torch.ones((length, length), dtype=_torch.bool),
                diagonal=1,
            )

        def forward(self, batch: Mapping[str, Any]) -> tuple[Any, Any]:
            attention_mask = batch["attention_mask"]
            if attention_mask.device.type != "cpu":
                raise NextBehaviorModelError("model inputs must remain on CPU")
            dense = _torch.cat(
                (
                    batch["phase_tactic_multi_hot"],
                    batch["phase_technique_multi_hot"],
                    batch["phase_source_multi_hot"],
                    batch["phase_confidence_multi_hot"],
                    batch["phase_agreement_multi_hot"],
                ),
                dim=-1,
            )
            states = self.phase_projection(dense)
            states = states + self.repetition_embedding(
                batch["phase_repetition_index"]
            )
            states = states + self.elapsed_embedding(
                batch["phase_elapsed_time_index"]
            )
            states = states + self.audit_embedding(
                batch["phase_audit_count_index"]
            )
            logical_positions = attention_mask.long().cumsum(dim=1) - 1
            logical_positions = logical_positions.clamp(min=0)
            states = states + self.position_embedding(logical_positions)
            context = (
                self.login_embedding(batch["context_login_outcome_index"])
                + self.command_count_embedding(
                    batch["context_command_count_index"]
                )
                + self.session_age_embedding(
                    batch["context_session_age_index"]
                )
                + self.transfer_embedding(
                    batch["context_confirmed_transfer"]
                )
            )
            states = states + context.unsqueeze(1)
            encoded = self.encoder(
                states,
                mask=self._causal_mask(states.size(1)),
                src_key_padding_mask=~attention_mask,
            )
            absolute_positions = _torch.arange(states.size(1)).unsqueeze(0)
            last_positions = absolute_positions.masked_fill(
                ~attention_mask, -1
            ).max(dim=1).values
            final = encoded[
                _torch.arange(encoded.size(0)),
                last_positions,
            ]
            return self.tactic_head(final), self.terminal_head(final).squeeze(-1)

else:

    class NextBehaviorCausalTransformer:  # pragma: no cover - no-Torch shim.
        def __init__(self, spec: Mapping[str, Any], *, seed: int = 0) -> None:
            del spec, seed
            _require_torch()


def build_model(
    spec: Mapping[str, Any],
    *,
    seed: int = 0,
) -> NextBehaviorCausalTransformer:
    """Construct a deterministically initialized CPU model."""

    _require_torch()
    model = NextBehaviorCausalTransformer(spec, seed=seed)
    model.eval()
    return model


def _integer(
    value: Any,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise NextBehaviorModelError(f"{field} is outside its frozen range")
    return value


def _matrix(
    value: Any,
    *,
    field: str,
    rows: int,
    columns: int,
) -> list[list[int]]:
    if not isinstance(value, list) or len(value) != rows:
        raise NextBehaviorModelError(f"{field} has an invalid row count")
    result: list[list[int]] = []
    for row_index, row in enumerate(value):
        if not isinstance(row, list) or len(row) != columns:
            raise NextBehaviorModelError(
                f"{field}[{row_index}] has an invalid column count"
            )
        output_row = []
        for column_index, item in enumerate(row):
            output_row.append(
                _integer(
                    item,
                    field=f"{field}[{row_index}][{column_index}]",
                    minimum=0,
                    maximum=1,
                )
            )
        result.append(output_row)
    return result


def _index_vector(
    value: Any,
    *,
    field: str,
    length: int,
    maximum: int,
) -> list[int]:
    if not isinstance(value, list) or len(value) != length:
        raise NextBehaviorModelError(f"{field} has an invalid length")
    return [
        _integer(
            item,
            field=f"{field}[{index}]",
            minimum=0,
            maximum=maximum,
        )
        for index, item in enumerate(value)
    ]


def require_valid_tensor_input(
    value: Any,
    spec: Mapping[str, Any],
) -> Dict[str, Any]:
    """Fail closed unless an adapter tensor exactly matches the model spec."""

    validated_spec = require_valid_model_spec(spec)
    if not isinstance(value, dict):
        raise NextBehaviorModelError("tensor input must be an object")
    if set(value) != _TENSOR_FIELDS:
        raise NextBehaviorModelError(
            "tensor input fields do not match the frozen tensor contract"
        )
    if value.get("schema_version") != TENSOR_SCHEMA_VERSION:
        raise NextBehaviorModelError("tensor schema version mismatch")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        raise NextBehaviorModelError("tensor target contract mismatch")
    for field in (
        "vocabulary_id",
        "vocabulary_sha256",
        "preprocessing_sha256",
    ):
        if value.get(field) != validated_spec[field]:
            raise NextBehaviorModelError(f"tensor {field} mismatch")
    dimensions = validated_spec["input_dimensions"]
    maximum = dimensions["maximum_sequence_length"]
    if value.get("maximum_sequence_length") != maximum:
        raise NextBehaviorModelError("tensor maximum sequence length mismatch")
    sequence_length = _integer(
        value.get("sequence_length"),
        field="sequence_length",
        minimum=1,
        maximum=maximum,
    )
    attention_mask = _index_vector(
        value.get("attention_mask"),
        field="attention_mask",
        length=maximum,
        maximum=1,
    )
    expected_mask = [0] * (maximum - sequence_length) + [1] * sequence_length
    if attention_mask != expected_mask:
        raise NextBehaviorModelError(
            "attention_mask must be canonical left padding"
        )
    padding = maximum - sequence_length

    matrix_dimensions = {
        "phase_tactic_multi_hot": "phase_tactic_count",
        "phase_technique_multi_hot": "phase_technique_count",
        "phase_source_multi_hot": "phase_source_count",
        "phase_confidence_multi_hot": "phase_confidence_count",
        "phase_agreement_multi_hot": "phase_agreement_count",
    }
    for field, dimension in matrix_dimensions.items():
        rows = _matrix(
            value.get(field),
            field=field,
            rows=maximum,
            columns=dimensions[dimension],
        )
        if any(any(row) for row in rows[:padding]):
            raise NextBehaviorModelError(
                f"{field} does not match the padding mask"
            )
    index_dimensions = {
        "phase_repetition_index": "repetition_category_count",
        "phase_elapsed_time_index": "elapsed_time_category_count",
        "phase_audit_count_index": "audit_count_category_count",
    }
    for field, dimension in index_dimensions.items():
        indices = _index_vector(
            value.get(field),
            field=field,
            length=maximum,
            maximum=dimensions[dimension],
        )
        if indices[:padding] != [0] * padding or any(
            index == 0 for index in indices[padding:]
        ):
            raise NextBehaviorModelError(
                f"{field} does not match the padding mask"
            )
    for field, dimension in (
        ("context_login_outcome_index", "login_outcome_category_count"),
        ("context_command_count_index", "command_count_category_count"),
        ("context_session_age_index", "session_age_category_count"),
    ):
        _integer(
            value.get(field),
            field=field,
            minimum=1,
            maximum=dimensions[dimension],
        )
    _integer(
        value.get("context_confirmed_transfer"),
        field="context_confirmed_transfer",
        minimum=0,
        maximum=1,
    )
    if not isinstance(value.get("source_input_hash"), str) or not (
        _SOURCE_INPUT_ID.fullmatch(value["source_input_hash"])
    ):
        raise NextBehaviorModelError("source_input_hash is invalid")
    tensor_payload = _without(value, "source_input_hash", "tensor_hash")
    expected_tensor_hash = stable_id("nextbehaviortensor", tensor_payload)
    if value.get("tensor_hash") != expected_tensor_hash:
        raise NextBehaviorModelError("tensor_hash does not match tensor content")
    return deepcopy(value)


def _prepare_batch(value: Mapping[str, Any], spec: Mapping[str, Any]) -> Dict[str, Any]:
    torch = _require_torch()
    tensor = require_valid_tensor_input(value, spec)
    batch: Dict[str, Any] = {}
    for field in (
        "phase_tactic_multi_hot",
        "phase_technique_multi_hot",
        "phase_source_multi_hot",
        "phase_confidence_multi_hot",
        "phase_agreement_multi_hot",
    ):
        batch[field] = torch.tensor(
            [tensor[field]], dtype=torch.float32, device="cpu"
        )
    batch["attention_mask"] = torch.tensor(
        [tensor["attention_mask"]], dtype=torch.bool, device="cpu"
    )
    for field in (
        "phase_repetition_index",
        "phase_elapsed_time_index",
        "phase_audit_count_index",
    ):
        batch[field] = torch.tensor(
            [tensor[field]], dtype=torch.long, device="cpu"
        )
    for field in (
        "context_login_outcome_index",
        "context_command_count_index",
        "context_session_age_index",
        "context_confirmed_transfer",
    ):
        batch[field] = torch.tensor(
            [tensor[field]], dtype=torch.long, device="cpu"
        )
    return batch


def predict_next_behavior(
    model: NextBehaviorCausalTransformer,
    tensor_input: Mapping[str, Any],
    *,
    spec: Mapping[str, Any],
) -> Dict[str, Any]:
    """Run deterministic CPU inference and return raw, uncalibrated logits."""

    torch = _require_torch()
    validated_spec = require_valid_model_spec(spec)
    if _module_spec(model) != validated_spec:
        raise NextBehaviorModelError("model and requested spec do not match")
    if any(parameter.device.type != "cpu" for parameter in model.parameters()):
        raise NextBehaviorModelError("model parameters must remain on CPU")
    batch = _prepare_batch(tensor_input, validated_spec)
    model.eval()
    with torch.inference_mode():
        tactic_logits, terminal_logits = model(batch)
    tactic_values = tactic_logits[0].tolist()
    return {
        "schema_version": MODEL_OUTPUT_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "model_spec_id": validated_spec["spec_id"],
        "model_spec_sha256": validated_spec["spec_sha256"],
        "source_tensor_hash": tensor_input["tensor_hash"],
        "score_semantics": "raw_uncalibrated_logits",
        "tactic_logits": {
            tactic: float(logit)
            for tactic, logit in zip(OUTPUT_TACTICS, tactic_values)
        },
        "terminal_label": validated_spec["output"]["terminal_label"],
        "terminal_logit": float(terminal_logits[0].item()),
    }


def state_dictionary_sha256(state_dict: Mapping[str, Any]) -> str:
    """Hash ordered tensor names, dtypes, shapes, and canonical CPU bytes."""

    torch = _require_torch()
    if not isinstance(state_dict, Mapping) or not state_dict:
        raise NextBehaviorCheckpointError("state_dict must be a non-empty mapping")
    digest = hashlib.sha256()
    for name in sorted(state_dict):
        tensor = state_dict[name]
        if not isinstance(name, str) or not torch.is_tensor(tensor):
            raise NextBehaviorCheckpointError(
                "state_dict must contain named tensors only"
            )
        canonical = tensor.detach().cpu().contiguous()
        header = stable_json(
            {
                "name": name,
                "dtype": str(canonical.dtype),
                "shape": list(canonical.shape),
            }
        ).encode("utf-8")
        raw = bytes(canonical.view(torch.uint8).reshape(-1).tolist())
        digest.update(len(header).to_bytes(8, "big"))
        digest.update(header)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _checkpoint_metadata(
    model: NextBehaviorCausalTransformer,
    spec: Mapping[str, Any],
    state_hash: str,
) -> Dict[str, Any]:
    torch = _require_torch()
    return {
        "schema_version": CHECKPOINT_METADATA_SCHEMA_VERSION,
        "model_spec_sha256": spec["spec_sha256"],
        "architecture_sha256": spec["architecture_sha256"],
        "vocabulary_sha256": spec["vocabulary_sha256"],
        "preprocessing_sha256": spec["preprocessing_sha256"],
        "state_dictionary_sha256": state_hash,
        "parameter_count": sum(
            parameter.numel() for parameter in model.parameters()
        ),
        "initialization_seed": model.initialization_seed,
        "saved_device": "cpu",
        "torch_version": str(torch.__version__),
    }


def save_checkpoint(
    path: str | Path,
    model: NextBehaviorCausalTransformer,
    *,
    spec: Mapping[str, Any],
) -> Dict[str, Any]:
    """Atomically save a CPU checkpoint and return its external hash receipt."""

    torch = _require_torch()
    validated_spec = require_valid_model_spec(spec)
    if _module_spec(model) != validated_spec:
        raise NextBehaviorCheckpointError("model and checkpoint spec do not match")
    if any(parameter.device.type != "cpu" for parameter in model.parameters()):
        raise NextBehaviorCheckpointError("only CPU checkpoints are permitted")
    state_dict = {
        name: tensor.detach().cpu().contiguous()
        for name, tensor in model.state_dict().items()
    }
    state_hash = state_dictionary_sha256(state_dict)
    metadata = _checkpoint_metadata(model, validated_spec, state_hash)
    payload = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "model_spec": validated_spec,
        "metadata": metadata,
        "state_dict": state_dict,
    }
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
        torch.save(payload, temporary_name)
        os.replace(temporary_name, destination)
    finally:
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass
    checkpoint_hash = sha256_file(destination)
    return {
        "schema_version": CHECKPOINT_RECEIPT_SCHEMA_VERSION,
        "checkpoint_sha256": checkpoint_hash,
        "state_dictionary_sha256": state_hash,
        "model_spec_sha256": validated_spec["spec_sha256"],
        "architecture_sha256": validated_spec["architecture_sha256"],
        "vocabulary_sha256": validated_spec["vocabulary_sha256"],
        "preprocessing_sha256": validated_spec["preprocessing_sha256"],
        "parameter_count": metadata["parameter_count"],
    }


def _require_checkpoint_payload(
    payload: Any,
    *,
    expected_spec: Mapping[str, Any],
) -> tuple[Dict[str, Any], Mapping[str, Any]]:
    if not isinstance(payload, dict) or set(payload) != _CHECKPOINT_FIELDS:
        raise NextBehaviorCheckpointError(
            "checkpoint fields do not match the frozen contract"
        )
    if payload.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        raise NextBehaviorCheckpointError("checkpoint schema version mismatch")
    embedded_spec = require_valid_model_spec(payload.get("model_spec"))
    if embedded_spec != expected_spec:
        raise NextBehaviorCheckpointError("checkpoint model spec mismatch")
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict) or set(metadata) != (
        _CHECKPOINT_METADATA_FIELDS
    ):
        raise NextBehaviorCheckpointError(
            "checkpoint metadata fields do not match the frozen contract"
        )
    if metadata.get("schema_version") != CHECKPOINT_METADATA_SCHEMA_VERSION:
        raise NextBehaviorCheckpointError(
            "checkpoint metadata schema version mismatch"
        )
    expected_metadata = {
        "model_spec_sha256": expected_spec["spec_sha256"],
        "architecture_sha256": expected_spec["architecture_sha256"],
        "vocabulary_sha256": expected_spec["vocabulary_sha256"],
        "preprocessing_sha256": expected_spec["preprocessing_sha256"],
        "saved_device": "cpu",
    }
    for field, expected in expected_metadata.items():
        if metadata.get(field) != expected:
            raise NextBehaviorCheckpointError(
                f"checkpoint metadata {field} mismatch"
            )
    if not _is_sha256(metadata.get("state_dictionary_sha256")):
        raise NextBehaviorCheckpointError(
            "checkpoint state_dictionary_sha256 is invalid"
        )
    for field in ("parameter_count", "initialization_seed"):
        value = metadata.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise NextBehaviorCheckpointError(
                f"checkpoint metadata {field} is invalid"
            )
    if not isinstance(metadata.get("torch_version"), str) or not metadata.get(
        "torch_version"
    ):
        raise NextBehaviorCheckpointError(
            "checkpoint metadata torch_version is invalid"
        )
    state_dict = payload.get("state_dict")
    if not isinstance(state_dict, Mapping) or not state_dict:
        raise NextBehaviorCheckpointError("checkpoint state_dict is invalid")
    return deepcopy(metadata), state_dict


def load_checkpoint(
    path: str | Path,
    *,
    expected_spec: Mapping[str, Any],
    expected_checkpoint_sha256: str,
) -> tuple[NextBehaviorCausalTransformer, Dict[str, Any]]:
    """Verify a checkpoint before deserialization and load it strictly on CPU."""

    torch = _require_torch()
    validated_spec = require_valid_model_spec(expected_spec)
    if not _is_sha256(expected_checkpoint_sha256):
        raise NextBehaviorCheckpointError(
            "expected_checkpoint_sha256 must be a SHA-256 digest"
        )
    checkpoint_path = Path(path)
    if not checkpoint_path.is_file():
        raise NextBehaviorCheckpointError("checkpoint path is missing")
    actual_checkpoint_hash = sha256_file(checkpoint_path)
    if actual_checkpoint_hash != expected_checkpoint_sha256:
        raise NextBehaviorCheckpointError("checkpoint SHA-256 mismatch")
    try:
        try:
            payload = torch.load(
                checkpoint_path,
                map_location=torch.device("cpu"),
                weights_only=True,
            )
        except TypeError:  # PyTorch versions before ``weights_only``.
            payload = torch.load(
                checkpoint_path,
                map_location=torch.device("cpu"),
            )
    except Exception as exc:
        raise NextBehaviorCheckpointError(
            "checkpoint deserialization failed"
        ) from exc
    metadata, state_dict = _require_checkpoint_payload(
        payload,
        expected_spec=validated_spec,
    )
    actual_state_hash = state_dictionary_sha256(state_dict)
    if actual_state_hash != metadata["state_dictionary_sha256"]:
        raise NextBehaviorCheckpointError("checkpoint state_dict hash mismatch")
    model = build_model(
        validated_spec,
        seed=metadata["initialization_seed"],
    )
    expected_keys = set(model.state_dict())
    if set(state_dict) != expected_keys:
        raise NextBehaviorCheckpointError(
            "checkpoint state_dict keys do not match the architecture"
        )
    try:
        model.load_state_dict(state_dict, strict=True)
    except (RuntimeError, TypeError, ValueError) as exc:
        raise NextBehaviorCheckpointError(
            "checkpoint state_dict is incompatible with the architecture"
        ) from exc
    parameter_count = sum(parameter.numel() for parameter in model.parameters())
    if parameter_count != metadata["parameter_count"]:
        raise NextBehaviorCheckpointError(
            "checkpoint parameter count does not match the architecture"
        )
    model.eval()
    returned_metadata = deepcopy(metadata)
    returned_metadata["checkpoint_sha256"] = actual_checkpoint_hash
    return model, returned_metadata
