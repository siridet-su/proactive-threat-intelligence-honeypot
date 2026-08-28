"""Isolated, non-authoritative next-distinct-tactic POC adapter."""

from .adapter import (
    ADAPTER_SCHEMA_VERSION,
    LABEL_ORDER,
    MAX_HISTORY,
    PocAdapterError,
    load_runtime_binding,
    prepare_history,
    predict_from_logits,
    temperature_scaled_softmax,
)

__all__ = [
    "ADAPTER_SCHEMA_VERSION",
    "LABEL_ORDER",
    "MAX_HISTORY",
    "PocAdapterError",
    "load_runtime_binding",
    "prepare_history",
    "predict_from_logits",
    "temperature_scaled_softmax",
]
