"""Fail-closed, production-independent next-distinct-tactic adapter.

This module deliberately has no database, canonical-analysis, storage, or
network imports.  It accepts trusted tactic observations and a caller-provided
logit vector; a future model loader may be attached only after a complete,
content-addressed runtime binding is approved.  It is therefore safe to test
locally without activating or replacing the current production runtime.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Mapping, Sequence

ADAPTER_SCHEMA_VERSION = "prediction_next_distinct_poc_adapter.v1"
MAX_HISTORY = 8
LABEL_ORDER = (
    "command-and-control",
    "credential-access",
    "defense-evasion",
    "discovery",
    "execution",
    "persistence",
    "privilege-escalation",
)


class PocAdapterError(ValueError):
    """Raised when the isolated POC contract cannot be satisfied."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_digest(value: Any, field: str) -> str:
    text = str(value or "").lower()
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise PocAdapterError(f"{field} must be a SHA-256 digest")
    return text


def _require_finite(value: Any, field: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise PocAdapterError(f"{field} must be finite") from exc
    if not math.isfinite(number):
        raise PocAdapterError(f"{field} must be finite")
    return number


def prepare_history(observations: Sequence[str]) -> dict[str, Any]:
    """Apply the frozen prediction-only sequence contract.

    Adjacent equal tactics are removed, non-adjacent revisits remain, and only
    the final eight deduplicated observations are visible to the model.
    """

    if isinstance(observations, (str, bytes)):
        raise PocAdapterError("observations must be a sequence of tactic labels")
    try:
        values = list(observations)
    except TypeError as exc:
        raise PocAdapterError("observations must be iterable") from exc
    for value in values:
        if value not in LABEL_ORDER:
            raise PocAdapterError(f"unknown tactic label: {value!r}")

    deduplicated: list[str] = []
    for value in values:
        if not deduplicated or deduplicated[-1] != value:
            deduplicated.append(value)
    visible = deduplicated[-MAX_HISTORY:]
    return {
        "sequence": visible,
        "history_visible_count": len(visible),
        "history_source_count": len(deduplicated),
        "history_truncated": len(deduplicated) > MAX_HISTORY,
        "adjacent_duplicates_removed": len(values) - len(deduplicated),
    }


def temperature_scaled_softmax(
    logits: Sequence[float], temperature: float, *, label_order: Sequence[str] = LABEL_ORDER
) -> list[float]:
    """Return a finite probability vector after scalar temperature scaling."""

    if len(logits) != len(label_order) or tuple(label_order) != LABEL_ORDER:
        raise PocAdapterError("logit length or label order does not match frozen vocabulary")
    t = _require_finite(temperature, "temperature")
    if t <= 0.0:
        raise PocAdapterError("temperature must be positive")
    raw = [_require_finite(value, "logit") / t for value in logits]
    maximum = max(raw)
    exponentials = [math.exp(value - maximum) for value in raw]
    total = sum(exponentials)
    if not math.isfinite(total) or total <= 0.0:
        raise PocAdapterError("softmax normalization failed")
    probabilities = [value / total for value in exponentials]
    if any(not math.isfinite(value) for value in probabilities):
        raise PocAdapterError("softmax produced non-finite probability")
    return probabilities


def load_runtime_binding(path: str | Path) -> dict[str, Any]:
    """Load and verify an approved runtime binding, failing closed otherwise."""

    binding_path = Path(path)
    if not binding_path.is_file():
        raise PocAdapterError("runtime binding is missing")
    try:
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PocAdapterError("runtime binding is malformed") from exc
    if not isinstance(binding, dict):
        raise PocAdapterError("runtime binding must be an object")
    if binding.get("status") != "COMPLETE_VALID":
        raise PocAdapterError("runtime binding is not COMPLETE_VALID")
    if binding.get("authority") != "non_authoritative":
        raise PocAdapterError("runtime binding authority is invalid")
    if binding.get("canonical_write_allowed") is not False:
        raise PocAdapterError("canonical writes must be disabled")
    labels = tuple(binding.get("label_order", ()))
    if labels != LABEL_ORDER:
        raise PocAdapterError("runtime binding label order differs from frozen vocabulary")
    checkpoint = binding.get("checkpoint_path")
    checkpoint_sha = _require_digest(binding.get("checkpoint_sha256"), "checkpoint_sha256")
    checkpoint_path = Path(checkpoint) if checkpoint else None
    if checkpoint_path is None or not checkpoint_path.is_file():
        raise PocAdapterError("runtime checkpoint is missing")
    if _sha256_file(checkpoint_path) != checkpoint_sha:
        raise PocAdapterError("runtime checkpoint SHA-256 mismatch")
    temperature = _require_finite(binding.get("temperature"), "temperature")
    if temperature <= 0.0:
        raise PocAdapterError("runtime temperature must be positive")
    return binding


def predict_from_logits(
    observations: Sequence[str],
    logits: Sequence[float],
    *,
    temperature: float,
    model_identifier: str,
    checkpoint_sha256: str,
) -> dict[str, Any]:
    """Render a non-authoritative result from already-computed model logits.

    Model loading is intentionally injected by the caller.  This keeps the
    adapter independent from canonical state and makes an unresolved binding
    impossible to hide behind a fallback model.
    """

    history = prepare_history(observations)
    probabilities = temperature_scaled_softmax(logits, temperature)
    ranked = sorted(
        range(len(LABEL_ORDER)), key=lambda index: (-probabilities[index], index)
    )
    return {
        "schema_version": ADAPTER_SCHEMA_VERSION,
        "authority": "non_authoritative",
        "canonical_write_allowed": False,
        "task": "next_observed_distinct_tactic",
        "model_identifier": str(model_identifier),
        "checkpoint_sha256": _require_digest(checkpoint_sha256, "checkpoint_sha256"),
        "history": history,
        "calibration": {
            "method": "temperature_scaled_softmax.v1",
            "temperature": _require_finite(temperature, "temperature"),
        },
        "top1": LABEL_ORDER[ranked[0]],
        "top3": [LABEL_ORDER[index] for index in ranked[:3]],
        "probabilities": probabilities,
        "warning": "prediction-only POC; not evidence, authority, guidance, or action",
    }
