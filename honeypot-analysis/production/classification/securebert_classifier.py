"""Private ModernBERT-based ATT&CK command-classifier adapter.

``securebert`` is retained as the historical project identifier for API and
configuration compatibility.  The verified executable model is a private
``ModernBertForSequenceClassification`` checkpoint.  Its output is a single,
uncalibrated top-softmax ATT&CK candidate; deterministic reviewed rules remain
the authority in the surrounding classification pipeline.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from production.reproduction.next_behavior.classifier_assets import (
    ClassifierAssetError,
    MODEL_ARCHITECTURE,
    MODEL_LABEL_COUNT,
    MODEL_MAX_TOKENS,
    MODEL_PARAMETER_COUNT,
    MODEL_TASK,
    MODEL_TYPE,
    load_securebert_runtime_contract,
    verify_securebert_runtime_assets,
)
from production.utils.config import ProductionConfig
from production.utils.sensitive_data import redact_exception_for_log
from production.utils.serialization import utc_now


CONFIDENCE_SEMANTICS = "uncalibrated_top_softmax_score"
TEMPERATURE_APPLIED = False
LEGACY_PROJECT_IDENTIFIER = "securebert"


class SecureBertInferenceError(ValueError):
    """Raised when model output cannot safely be interpreted."""


def _flatten_values(value: Any) -> List[Any]:
    if hasattr(value, "detach"):
        value = value.detach()
    if hasattr(value, "cpu"):
        value = value.cpu()
    if hasattr(value, "tolist"):
        value = value.tolist()
    if isinstance(value, (list, tuple)):
        flattened: List[Any] = []
        for item in value:
            flattened.extend(_flatten_values(item))
        return flattened
    return [value]


def _sequence_length(value: Any) -> Optional[int]:
    if hasattr(value, "detach"):
        value = value.detach()
    if hasattr(value, "cpu"):
        value = value.cpu()
    if hasattr(value, "tolist"):
        value = value.tolist()
    while isinstance(value, (list, tuple)) and len(value) == 1:
        value = value[0]
    if isinstance(value, (list, tuple)):
        return len(value)
    return None


def _attention_count(value: Any) -> Optional[int]:
    values = _flatten_values(value)
    if not values:
        return None
    try:
        return sum(1 for item in values if int(item) != 0)
    except (TypeError, ValueError):
        return None


class SecureBertCommandClassifier:
    """Load the verified private model and return ``(ttp_id, score)`` tuples."""

    legacy_project_identifier = LEGACY_PROJECT_IDENTIFIER
    verified_model_architecture = MODEL_ARCHITECTURE
    model_type = MODEL_TYPE
    task = MODEL_TASK
    confidence_semantics = CONFIDENCE_SEMANTICS
    temperature_applied = TEMPERATURE_APPLIED

    def __init__(
        self,
        model_path: str,
        checkpoint_path: str = "",
        device: str = "auto",
        max_length: int = MODEL_MAX_TOKENS,
        *,
        runtime_asset_contract: Mapping[str, Any] | None = None,
        repository_root: Path | None = None,
        verify_asset_identity: bool = True,
    ) -> None:
        self.max_length = int(max_length)
        self.model_path = Path(model_path).expanduser()
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"private ModernBERT model path not found: {self.model_path}"
            )

        if checkpoint_path:
            self.checkpoint_path = Path(checkpoint_path).expanduser()
        else:
            default_checkpoint = self.model_path / "checkpoint-6765"
            self.checkpoint_path = (
                default_checkpoint if default_checkpoint.exists() else self.model_path
            )
        if not self.checkpoint_path.exists():
            raise FileNotFoundError(
                f"private ModernBERT checkpoint path not found: {self.checkpoint_path}"
            )

        self.runtime_asset_contract: Dict[str, Any] | None = (
            dict(runtime_asset_contract) if runtime_asset_contract is not None else None
        )
        self.runtime_asset_identity: Dict[str, Any] = {
            "status": "unbound_legacy_constructor"
        }
        if self.runtime_asset_contract is not None and verify_asset_identity:
            self.runtime_asset_identity = verify_securebert_runtime_assets(
                self.runtime_asset_contract,
                model_root=self.model_path,
            )
            expected_checkpoint = (
                self.model_path / self.runtime_asset_contract["checkpoint"]["path"]
            ).resolve()
            actual_checkpoint = (
                self.checkpoint_path / "model.safetensors"
                if self.checkpoint_path.is_dir()
                else self.checkpoint_path
            ).resolve()
            if actual_checkpoint != expected_checkpoint:
                raise ClassifierAssetError(
                    "SecureBERT checkpoint path is not the bound runtime asset"
                )
            if self.max_length != MODEL_MAX_TOKENS:
                raise ClassifierAssetError(
                    "SecureBERT max_length differs from the bound runtime contract"
                )

        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(
                "The private ModernBERT classifier requires torch and transformers "
                "in the runtime image."
            ) from exc

        self.torch = torch
        if device == "auto":
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_path))
        loaded_model = AutoModelForSequenceClassification.from_pretrained(
            str(self.checkpoint_path)
        )
        self._validate_loaded_model(loaded_model)
        self.model = loaded_model.to(self.device)
        self.model.eval()
        self.last_inference_metadata: Dict[str, Any] = {
            "status": "loaded",
            "confidence_semantics": CONFIDENCE_SEMANTICS,
            "temperature_applied": False,
            "max_model_tokens": self.max_length,
        }
        self.last_batch_inference_metadata: List[Dict[str, Any]] = []

    def _validate_loaded_model(self, model: Any) -> None:
        config = getattr(model, "config", None)
        if config is None:
            raise ClassifierAssetError("SecureBERT model configuration is unavailable")
        architectures = getattr(config, "architectures", None) or []
        if self.runtime_asset_contract is not None and MODEL_ARCHITECTURE not in architectures:
            raise ClassifierAssetError("SecureBERT loaded model architecture mismatch")
        if self.runtime_asset_contract is not None and getattr(config, "model_type", None) != MODEL_TYPE:
            raise ClassifierAssetError("SecureBERT loaded model type mismatch")
        raw_labels = getattr(config, "id2label", None) or {}
        normalized: Dict[str, str] = {}
        expected_indexes = (
            range(MODEL_LABEL_COUNT)
            if self.runtime_asset_contract is not None
            else range(len(raw_labels))
        )
        for index in expected_indexes:
            value = raw_labels.get(str(index), raw_labels.get(index))
            if not isinstance(value, str) or not value.strip():
                raise ClassifierAssetError("SecureBERT loaded label mapping is incomplete")
            normalized[str(index)] = value.strip()
        self.id2label = normalized
        expected_count = (
            self.runtime_asset_contract.get("num_labels", MODEL_LABEL_COUNT)
            if self.runtime_asset_contract is not None
            else len(normalized)
        )
        if len(normalized) != expected_count:
            raise ClassifierAssetError("SecureBERT loaded label count mismatch")
        if self.runtime_asset_contract is not None:
            expected_parameter_count = self.runtime_asset_contract.get(
                "parameter_count", MODEL_PARAMETER_COUNT
            )
            try:
                parameter_count = sum(
                    int(parameter.numel()) for parameter in model.parameters()
                )
            except (AttributeError, TypeError, ValueError) as exc:
                raise ClassifierAssetError(
                    "SecureBERT loaded parameter identity is unavailable"
                ) from exc
            if parameter_count != expected_parameter_count:
                raise ClassifierAssetError("SecureBERT loaded parameter count mismatch")
            bound_labels = self.runtime_asset_contract["label_space"][
                "ordered_labels_sha256"
            ]
            from production.reproduction.next_behavior.classifier_assets import (
                ordered_label_sha256,
            )

            if ordered_label_sha256(list(normalized.values())) != bound_labels:
                raise ClassifierAssetError("SecureBERT loaded label order mismatch")

    def _count_tokens(self, command: str) -> Optional[int]:
        try:
            encoder = getattr(self.tokenizer, "encode", None)
            if callable(encoder):
                return _sequence_length(encoder(command, add_special_tokens=True))
            encoded = self.tokenizer(
                command,
                add_special_tokens=True,
                truncation=False,
                padding=False,
            )
            if hasattr(encoded, "get"):
                return _sequence_length(encoded.get("input_ids"))
            return None
        except Exception:
            return None

    def _move_to_device(self, inputs: Any) -> Any:
        mover = getattr(inputs, "to", None)
        return mover(self.device) if callable(mover) else inputs

    def _build_inputs(
        self,
        command: str | Sequence[str],
        *,
        max_length: int,
    ) -> tuple[Any, List[Optional[int]], List[Optional[int]]]:
        commands = [command] if isinstance(command, str) else list(command)
        pre_counts = [self._count_tokens(str(item)) for item in commands]
        inputs = self.tokenizer(
            command,
            return_tensors="pt",
            truncation=True,
            max_length=max_length,
            padding=True,
        )
        effective_counts: List[Optional[int]] = []
        attention = inputs.get("attention_mask") if hasattr(inputs, "get") else None
        if attention is not None:
            values = attention.tolist() if hasattr(attention, "tolist") else attention
            if isinstance(values, (list, tuple)) and values and isinstance(
                values[0], (list, tuple)
            ):
                effective_counts = [_attention_count(item) for item in values]
            else:
                effective_counts = [_attention_count(values)]
        if len(effective_counts) != len(commands):
            input_ids = inputs.get("input_ids") if hasattr(inputs, "get") else None
            length = _sequence_length(input_ids)
            effective_counts = [length for _ in commands]
        self.last_batch_inference_metadata = []
        for pre_count, effective_count in zip(pre_counts, effective_counts):
            truncated = bool(pre_count is not None and pre_count > max_length)
            self.last_batch_inference_metadata.append(
                {
                    "status": "model_input_ready",
                    "pre_truncation_token_count": pre_count,
                    "effective_token_count": effective_count,
                    "max_model_tokens": max_length,
                    "truncated": truncated,
                    "model_input_complete": pre_count is not None and not truncated,
                    "confidence_semantics": CONFIDENCE_SEMANTICS,
                    "temperature_applied": False,
                }
            )
        return self._move_to_device(inputs), pre_counts, effective_counts

    def _set_failure(self, status: str, error: Exception | str) -> None:
        self.last_inference_metadata = {
            "status": status,
            "error": type(error).__name__ if isinstance(error, Exception) else str(error),
            "confidence_semantics": CONFIDENCE_SEMANTICS,
            "temperature_applied": False,
            "max_model_tokens": self.max_length,
        }

    def _validate_logits(self, logits: Any) -> None:
        shape = getattr(logits, "shape", None)
        if shape is None:
            raw = logits.tolist() if hasattr(logits, "tolist") else logits
            if isinstance(raw, (list, tuple)) and raw and isinstance(
                raw[0], (list, tuple)
            ):
                shape = (len(raw), len(raw[0]))
        try:
            shape_tuple = tuple(int(value) for value in shape)
        except (TypeError, ValueError):
            raise SecureBertInferenceError(
                "MODEL_INVALID_NUMERIC_OUTPUT: logits shape unavailable"
            )
        expected = len(self.id2label)
        if len(shape_tuple) != 2 or shape_tuple[0] < 1 or shape_tuple[1] != expected:
            raise SecureBertInferenceError(
                "MODEL_INVALID_NUMERIC_OUTPUT: logits shape is incompatible with label space"
            )
        try:
            values = _flatten_values(logits)
            if any(not math.isfinite(float(value)) for value in values):
                raise SecureBertInferenceError(
                    "MODEL_INVALID_NUMERIC_OUTPUT: logits contain a non-finite value"
                )
        except SecureBertInferenceError:
            raise
        except (TypeError, ValueError) as exc:
            raise SecureBertInferenceError(
                "MODEL_INVALID_NUMERIC_OUTPUT: logits are not numeric"
            ) from exc

    def _classify_with_inputs(self, inputs: Any) -> Tuple[Optional[str], float]:
        with self.torch.no_grad():
            logits = self.model(**inputs).logits
        self._validate_logits(logits)
        probs = self.torch.softmax(logits, dim=-1)
        self._validate_logits(probs)
        values = _flatten_values(probs)
        if any(not math.isfinite(float(value)) for value in values):
            raise SecureBertInferenceError(
                "MODEL_INVALID_NUMERIC_OUTPUT: softmax contains a non-finite value"
            )
        idx = int(probs.argmax().item())
        confidence = float(probs[0][idx].item())
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise SecureBertInferenceError(
                "MODEL_INVALID_NUMERIC_OUTPUT: top score is outside [0,1]"
            )
        ttp_id = self.id2label.get(str(idx))
        if not ttp_id:
            raise SecureBertInferenceError(
                "MODEL_INVALID_NUMERIC_OUTPUT: selected label is missing"
            )
        return ttp_id, confidence

    def classify(self, command: str) -> Tuple[Optional[str], float]:
        command = (command or "").strip()
        if len(command) < 3:
            self.last_inference_metadata = {
                "status": "short_input_skipped",
                "model_input_evaluated": False,
                "pre_truncation_token_count": 0,
                "effective_token_count": 0,
                "max_model_tokens": self.max_length,
                "truncated": False,
                "model_input_complete": True,
                "confidence_semantics": CONFIDENCE_SEMANTICS,
                "temperature_applied": False,
            }
            return None, 0.0
        try:
            inputs, _pre, _effective = self._build_inputs(
                command, max_length=self.max_length
            )
            self.last_inference_metadata = dict(self.last_batch_inference_metadata[0])
            self.last_inference_metadata["model_input_evaluated"] = True
            return self._classify_with_inputs(inputs)
        except SecureBertInferenceError as exc:
            self._set_failure("MODEL_INVALID_NUMERIC_OUTPUT", exc)
            return None, 0.0
        except Exception as exc:
            self._set_failure("MODEL_INFERENCE_ERROR", exc)
            return None, 0.0

    def classify_batch(self, commands: List[str]) -> List[Tuple[Optional[str], float]]:
        if not commands:
            self.last_batch_inference_metadata = []
            return []
        try:
            inputs, _pre, _effective = self._build_inputs(
                commands, max_length=self.max_length
            )
            with self.torch.no_grad():
                logits = self.model(**inputs).logits
            self._validate_logits(logits)
            probs = self.torch.softmax(logits, dim=-1)
            self._validate_logits(probs)
            max_p, idx = self.torch.max(probs, dim=1)
            outputs: List[Tuple[Optional[str], float]] = []
            for probability, index in zip(max_p.tolist(), idx.tolist()):
                score = float(probability)
                if not math.isfinite(score) or not 0.0 <= score <= 1.0:
                    raise SecureBertInferenceError(
                        "MODEL_INVALID_NUMERIC_OUTPUT: batch score is invalid"
                    )
                outputs.append((self.id2label.get(str(int(index))), score))
            if any(label is None for label, _score in outputs):
                raise SecureBertInferenceError(
                    "MODEL_INVALID_NUMERIC_OUTPUT: batch label is missing"
                )
            return outputs
        except SecureBertInferenceError as exc:
            self._set_failure("MODEL_INVALID_NUMERIC_OUTPUT", exc)
            return [(None, 0.0) for _ in commands]
        except Exception as exc:
            self._set_failure("MODEL_INFERENCE_ERROR", exc)
            return [(None, 0.0) for _ in commands]

    def classify_topk(
        self, command: str, k: int = 3
    ) -> List[Tuple[Optional[str], float]]:
        command = (command or "").strip()
        if not command:
            self.last_inference_metadata = {
                "status": "empty_input_skipped",
                "model_input_evaluated": False,
                "max_model_tokens": max(self.max_length, 512),
                "truncated": False,
                "model_input_complete": True,
                "confidence_semantics": CONFIDENCE_SEMANTICS,
                "temperature_applied": False,
            }
            return []
        topk_length = max(self.max_length, 512)
        try:
            inputs, _pre, _effective = self._build_inputs(command, max_length=topk_length)
            self.last_inference_metadata = dict(self.last_batch_inference_metadata[0])
            self.last_inference_metadata["max_model_tokens"] = topk_length
            self.last_inference_metadata["model_input_evaluated"] = True
            with self.torch.no_grad():
                logits = self.model(**inputs).logits
            self._validate_logits(logits)
            probs = self.torch.softmax(logits, dim=-1)
            self._validate_logits(probs)
            top_p, top_idx = self.torch.topk(probs, k=k, dim=1)
            outputs = []
            for probability, index in zip(top_p[0].tolist(), top_idx[0].tolist()):
                score = float(probability)
                if not math.isfinite(score) or not 0.0 <= score <= 1.0:
                    raise SecureBertInferenceError(
                        "MODEL_INVALID_NUMERIC_OUTPUT: top-k score is invalid"
                    )
                outputs.append((self.id2label.get(str(int(index))), score))
            if any(label is None for label, _score in outputs):
                raise SecureBertInferenceError(
                    "MODEL_INVALID_NUMERIC_OUTPUT: top-k label is missing"
                )
            return outputs
        except SecureBertInferenceError as exc:
            self._set_failure("MODEL_INVALID_NUMERIC_OUTPUT", exc)
            return []
        except Exception as exc:
            self._set_failure("MODEL_INFERENCE_ERROR", exc)
            return []


def _resolve_repository_root(environment: Mapping[str, Any] | None) -> Path:
    if environment:
        receipt_path = str(environment.get("receipt_path") or "").strip()
        if receipt_path:
            return Path(receipt_path).resolve().parents[1]
    return Path.cwd().resolve()


def _resolve_config_path(value: str, *, repository_root: Path) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else repository_root / path


def _load_runtime_contract(
    environment: Mapping[str, Any], *, repository_root: Path
) -> tuple[Dict[str, Any], str]:
    classifier = environment.get("classifier") or {}
    path_text = str(classifier.get("runtime_asset_contract_path") or "").strip()
    expected = str(classifier.get("runtime_asset_contract_sha256") or "").strip().lower()
    if not path_text or not expected:
        raise ClassifierAssetError("SecureBERT runtime asset contract binding is missing")
    path = repository_root / path_text
    if not path.is_file() or path.is_symlink():
        raise ClassifierAssetError("SecureBERT runtime asset contract is unavailable")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ClassifierAssetError("SecureBERT runtime asset contract SHA-256 mismatch")
    return load_securebert_runtime_contract(path), actual


def load_securebert_classifier(
    config: ProductionConfig,
    classifier_environment: Mapping[str, Any] | None = None,
):
    """Return a metadata-carrying callable, or ``None`` on model failure.

    Environment/source/policy verification is performed before model
    construction.  Model-only failures remain advisory failures: deterministic
    rule classification continues and no learned candidate is fabricated.
    """

    if not config.enable_securebert:
        return None
    try:
        environment = classifier_environment
        if environment is None:
            from production.classification.environment import load_classifier_environment

            environment = load_classifier_environment(
                getattr(config, "classifier_environment_path", ""),
                verify_assets=True,
            )
        repository_root = _resolve_repository_root(environment)
        contract, contract_sha256 = _load_runtime_contract(
            environment, repository_root=repository_root
        )
        classifier_config = environment.get("classifier") or {}
        model_path = _resolve_config_path(
            str(config.securebert_model_path), repository_root=repository_root
        )
        checkpoint_text = str(config.securebert_checkpoint_path or "").strip()
        checkpoint_path = (
            _resolve_config_path(checkpoint_text, repository_root=repository_root)
            if checkpoint_text
            else model_path / "checkpoint-6765"
        )
        if int(config.securebert_max_length) != int(
            classifier_config.get("max_length", MODEL_MAX_TOKENS)
        ):
            raise ClassifierAssetError("configured SecureBERT max length is not bound")
        classifier = SecureBertCommandClassifier(
            model_path=str(model_path),
            checkpoint_path=str(checkpoint_path),
            device=config.securebert_device,
            max_length=config.securebert_max_length,
            runtime_asset_contract=contract,
            repository_root=repository_root,
        )
        print(
            json.dumps(
                {
                    "service": "private_modernbert_command_classifier",
                    "legacy_project_identifier": LEGACY_PROJECT_IDENTIFIER,
                    "verified_model_architecture": MODEL_ARCHITECTURE,
                    "status": "loaded",
                    "model_path": str(classifier.model_path),
                    "checkpoint_path": str(classifier.checkpoint_path),
                    "checkpoint_sha256": contract["checkpoint"]["sha256"],
                    "runtime_asset_contract_sha256": contract_sha256,
                    "label_count": MODEL_LABEL_COUNT,
                    "max_model_tokens": MODEL_MAX_TOKENS,
                    "confidence_semantics": CONFIDENCE_SEMANTICS,
                    "temperature_applied": False,
                    "device": str(classifier.device),
                    "timestamp": utc_now(),
                },
                sort_keys=True,
            ),
            flush=True,
        )

        def bound_classify(command: str) -> Tuple[Optional[str], float]:
            result = classifier.classify(command)
            bound_classify.last_inference_metadata = dict(
                classifier.last_inference_metadata
            )
            return result

        bound_classify.__securebert_classifier__ = classifier
        bound_classify.runtime_asset_identity = dict(classifier.runtime_asset_identity)
        bound_classify.last_inference_metadata = dict(classifier.last_inference_metadata)
        return bound_classify
    except Exception as exc:
        print(
            json.dumps(
                {
                    "service": "private_modernbert_command_classifier",
                    "legacy_project_identifier": LEGACY_PROJECT_IDENTIFIER,
                    "verified_model_architecture": MODEL_ARCHITECTURE,
                    "status": "unavailable",
                    "error": redact_exception_for_log(exc),
                    "timestamp": utc_now(),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return None
