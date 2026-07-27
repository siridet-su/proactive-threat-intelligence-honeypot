"""Lightweight health presentation for the active predictor or VOMM rollback."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

from production.utils.serialization import utc_now


def infer_prediction_paths(
    policy: Optional[Dict[str, Any]] = None,
    *,
    environ: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    policy = policy or {}
    env = environ if environ is not None else os.environ
    mode = str(policy.get("prediction_mode") or "")
    if mode == "professor_approved_corrected_target_transformer_poc":
        model = str(
            env.get("NEXT_BEHAVIOR_TRANSFORMER_CHECKPOINT")
            or policy.get("checkpoint_path")
            or ""
        )
    else:
        model = str(
            env.get("EXTERNAL_SEED_MODEL_PATH")
            or policy.get("external_transition_model_path")
            or ""
        )
    return {
        "model": model,
        "validation": "",
        "review": "",
        "health": "",
        "mode": mode,
    }

def load_prediction_health(
    _health_path: str = "",
    *,
    model_path: str = "",
    validation_path: str = "",
    review_path: str = "",
    include_review: bool = False,
    mode: str = "",
) -> Dict[str, Any]:
    """Return compatibility-shaped health without legacy experiment analysis."""

    path = Path(model_path) if model_path else None
    available = bool(path and path.is_file())
    return {
        "schema_version": "prediction_health.v1",
        "generated_at": utc_now(),
        "available": available,
        "paths": {
            "model": model_path,
            "validation": "",
            "review": "",
        },
        "model": {
            "path": model_path,
            "source_type": mode or "configured_predictor",
        },
        "classification_quality": {},
        "validation": {},
        "review_queue": {},
        "warnings": (
            []
            if available
            else ["Configured prediction artifact is not available to this process."]
        ),
        "authority": "advisory_forecast_only",
        "legacy_external_seed_analysis_removed": True,
    }
