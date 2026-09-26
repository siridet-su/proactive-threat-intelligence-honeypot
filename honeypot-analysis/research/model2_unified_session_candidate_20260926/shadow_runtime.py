"""Fail-closed runtime for the controlled 54F unified Model2 PoC.

This runtime is intentionally disconnected from production authority and RRF.
It can be used by a future episode-wide source adapter to exercise the exact
artifact identity without changing the frozen 32F shadow path.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .contract import FEATURE_ORDER, FEATURE_SCHEMA_SHA256, LABEL_ORDER, SCHEMA_ID
from .pipeline import extract_or_unavailable


RESULT_SCHEMA = "model2_unified_54f_controlled_poc_shadow_result.v1"
AUTHORITY = "NON_AUTHORITATIVE_RESEARCH_SHADOW_ONLY"
MODEL_KIND = "STANDARDIZED_OVR_LOGISTIC_REGRESSION"


class ShadowRuntimeError(ValueError):
    pass


@dataclass(frozen=True)
class Head:
    weights: tuple[float, ...]
    bias: float
    threshold: float


@dataclass(frozen=True)
class LoadedCandidate:
    artifact_file_sha256: str
    canonical_model_identity_sha256: str
    feature_schema_sha256: str
    selected_indices: tuple[int, ...]
    means: tuple[float, ...]
    scales: tuple[float, ...]
    heads: Mapping[str, Head]
    t1105_controlled_gate: str


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ShadowRuntimeError(f"json_unreadable:{path.name}") from exc
    if not isinstance(value, dict):
        raise ShadowRuntimeError(f"json_not_object:{path.name}")
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _finite(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise ShadowRuntimeError(f"boolean_numeric:{field}")
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ShadowRuntimeError(f"numeric_invalid:{field}") from exc
    if not math.isfinite(result):
        raise ShadowRuntimeError(f"numeric_nonfinite:{field}")
    return result


def load_candidate(
    artifact_path: str | Path,
    *,
    feature_schema_path: str | Path,
    candidate_manifest_path: str | Path,
) -> LoadedCandidate:
    artifact_file = Path(artifact_path)
    schema_file = Path(feature_schema_path)
    manifest_file = Path(candidate_manifest_path)
    artifact = _read(artifact_file)
    schema = _read(schema_file)
    manifest = _read(manifest_file)
    artifact_file_sha = _sha(artifact_file)
    schema_file_sha = _sha(schema_file)
    if manifest.get("authority") != "RESEARCH_ONLY_NON_AUTHORITATIVE" or manifest.get("production_ready") is not False:
        raise ShadowRuntimeError("manifest_authority_invalid")
    if manifest.get("separate_t1105_model") is not False or manifest.get("model_type") != "UNIFIED_MULTI_OUTPUT_OVR_LOGISTIC_RESEARCH_POC":
        raise ShadowRuntimeError("manifest_unified_model_contract_invalid")
    controlled_gate = manifest.get("t1105_controlled_gate")
    if controlled_gate not in {"ALLOW_CONTROLLED_RESEARCH_ONLY", "BLOCK"}:
        raise ShadowRuntimeError("manifest_t1105_controlled_gate_invalid")
    if manifest.get("production_t1105_gate") != "BLOCK" or manifest.get("t1105_ensemble_gate") != "BLOCK":
        raise ShadowRuntimeError("manifest_production_gate_must_remain_blocked")
    if controlled_gate == "ALLOW_CONTROLLED_RESEARCH_ONLY" and (
        manifest.get("conflicting_feature_label_collisions") != 0
        or manifest.get("matched_benign_content_transfer_pass") is not True
        or int(manifest.get("matched_benign_content_transfer_pairs", 0)) <= 0
    ):
        raise ShadowRuntimeError("manifest_controlled_t1105_gate_evidence_invalid")
    if manifest.get("serialized_artifact_sha256") != artifact_file_sha:
        raise ShadowRuntimeError("artifact_file_sha256_mismatch")
    if manifest.get("feature_schema_sha256") != schema_file_sha or schema_file_sha != FEATURE_SCHEMA_SHA256:
        raise ShadowRuntimeError("feature_schema_sha256_mismatch")
    if schema.get("schema_id") != SCHEMA_ID or tuple(schema.get("feature_order", ())) != FEATURE_ORDER:
        raise ShadowRuntimeError("feature_schema_contract_mismatch")
    if artifact.get("warning") != "CONTROLLED_SYNTHETIC_POC_NOT_REAL_WORLD_ACCURACY":
        raise ShadowRuntimeError("artifact_research_warning_missing")
    if artifact.get("model_kind") != MODEL_KIND or artifact.get("architecture") != "UNIFIED_ARTIFACT_WITH_THREE_OVR_HEADS":
        raise ShadowRuntimeError("artifact_model_kind_invalid")
    semantics = artifact.get("label_semantics")
    if not isinstance(semantics, Mapping) or semantics.get("T1105") != "SESSION_BOUND_TRANSFER_ACTIVITY":
        raise ShadowRuntimeError("artifact_t1105_semantics_invalid")
    training_protocol = artifact.get("training_protocol")
    if not isinstance(training_protocol, Mapping) or training_protocol.get("score_semantics") != "SIGMOID_DECISION_SCORE_NOT_CALIBRATED_PROBABILITY":
        raise ShadowRuntimeError("artifact_score_semantics_invalid")
    if artifact.get("production_use") is not False or artifact.get("feature_schema_sha256") != FEATURE_SCHEMA_SHA256:
        raise ShadowRuntimeError("artifact_authority_or_schema_invalid")
    if tuple(artifact.get("feature_order", ())) != FEATURE_ORDER:
        raise ShadowRuntimeError("artifact_feature_order_mismatch")
    if artifact.get("artifact_sha256") != manifest.get("canonical_model_identity_sha256"):
        raise ShadowRuntimeError("canonical_model_identity_mismatch")
    indices_raw = artifact.get("selected_feature_indices")
    if not isinstance(indices_raw, list) or not indices_raw or any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >= len(FEATURE_ORDER)
        for value in indices_raw
    ) or len(set(indices_raw)) != len(indices_raw):
        raise ShadowRuntimeError("selected_feature_indices_invalid")
    indices = tuple(indices_raw)
    if artifact.get("selected_feature_names") != [FEATURE_ORDER[index] for index in indices]:
        raise ShadowRuntimeError("selected_feature_name_binding_mismatch")
    standardizer = artifact.get("standardizer")
    if not isinstance(standardizer, Mapping):
        raise ShadowRuntimeError("standardizer_missing")
    means_raw, scales_raw = standardizer.get("means"), standardizer.get("scales")
    if not isinstance(means_raw, list) or not isinstance(scales_raw, list) or len(means_raw) != len(FEATURE_ORDER) or len(scales_raw) != len(FEATURE_ORDER):
        raise ShadowRuntimeError("standardizer_dimension_mismatch")
    means = tuple(_finite(value, f"mean:{index}") for index, value in enumerate(means_raw))
    scales = tuple(_finite(value, f"scale:{index}") for index, value in enumerate(scales_raw))
    if any(value <= 0 for value in scales):
        raise ShadowRuntimeError("standardizer_scale_invalid")
    heads_raw = artifact.get("heads")
    if not isinstance(heads_raw, Mapping) or tuple(heads_raw) != LABEL_ORDER:
        raise ShadowRuntimeError("head_order_invalid")
    heads: dict[str, Head] = {}
    for label in LABEL_ORDER:
        raw = heads_raw[label]
        if not isinstance(raw, Mapping) or not isinstance(raw.get("weights"), list) or len(raw["weights"]) != len(indices):
            raise ShadowRuntimeError(f"head_dimension_invalid:{label}")
        heads[label] = Head(
            weights=tuple(_finite(value, f"weight:{label}:{index}") for index, value in enumerate(raw["weights"])),
            bias=_finite(raw.get("bias"), f"bias:{label}"),
            threshold=_finite(raw.get("threshold"), f"threshold:{label}"),
        )
        if not 0 < heads[label].threshold < 1:
            raise ShadowRuntimeError(f"threshold_out_of_range:{label}")
    return LoadedCandidate(
        artifact_file_sha256=artifact_file_sha,
        canonical_model_identity_sha256=str(artifact["artifact_sha256"]),
        feature_schema_sha256=schema_file_sha,
        selected_indices=indices,
        means=means,
        scales=scales,
        heads=heads,
        t1105_controlled_gate=str(controlled_gate),
    )


def _sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def _unavailable(reason: str, model: LoadedCandidate | None = None) -> dict[str, Any]:
    return {
        "schema_version": RESULT_SCHEMA,
        "status": "UNAVAILABLE",
        "availability": "UNAVAILABLE",
        "authority": AUTHORITY,
        "reason": reason[:240],
        "model_artifact_sha256": model.artifact_file_sha256 if model else None,
        "canonical_model_identity_sha256": model.canonical_model_identity_sha256 if model else None,
        "canonical_write_authority": False,
        "response_authority": False,
        "rrf_vote_eligible": False,
        "outputs": {
            label: {"availability": "UNAVAILABLE", "decision": None, "decision_score": None, "ensemble_vote_eligible": False}
            for label in LABEL_ORDER
        },
    }


def infer_envelope(
    envelope: Mapping[str, Any],
    model: LoadedCandidate,
    *,
    expected_identity: Mapping[str, Any],
) -> dict[str, Any]:
    extracted = extract_or_unavailable(envelope, expected_identity=expected_identity)
    if extracted.get("status") != "AVAILABLE":
        return _unavailable(f"feature_materialization:{extracted.get('reason_code', 'unavailable')}", model)
    vector = extracted.get("feature_vector")
    if not isinstance(vector, Mapping) or tuple(vector) != FEATURE_ORDER:
        return _unavailable("feature_vector_contract_mismatch", model)
    try:
        values = tuple(_finite(vector[name], f"feature:{name}") for name in FEATURE_ORDER)
        selected = tuple((values[index] - model.means[index]) / model.scales[index] for index in model.selected_indices)
        outputs: dict[str, Any] = {}
        for label in LABEL_ORDER:
            head = model.heads[label]
            linear = head.bias + math.fsum(weight * value for weight, value in zip(head.weights, selected))
            score = _sigmoid(linear)
            outputs[label] = {
                "availability": "AVAILABLE",
                "decision": "PRESENT" if score >= head.threshold else "ABSENT",
                "decision_score": score,
                "score_semantics": "SIGMOID_DECISION_SCORE_NOT_CALIBRATED_PROBABILITY",
                "threshold": head.threshold,
                # Every head remains advisory-only until exact baseline and
                # paired non-regression gates are completed.
                "ensemble_vote_eligible": False,
            }
        return {
            "schema_version": RESULT_SCHEMA,
            "status": "VALID_RESEARCH_SHADOW",
            "availability": "AVAILABLE",
            "authority": AUTHORITY,
            "identity": dict(expected_identity),
            "model_artifact_sha256": model.artifact_file_sha256,
            "canonical_model_identity_sha256": model.canonical_model_identity_sha256,
            "feature_schema_sha256": model.feature_schema_sha256,
            "feature_count": len(FEATURE_ORDER),
            "output_order": list(LABEL_ORDER),
            "one_unified_artifact": True,
            "canonical_write_authority": False,
            "response_authority": False,
            "rrf_vote_eligible": False,
            "t1105_gate": model.t1105_controlled_gate,
            "production_t1105_gate": "BLOCK",
            "t1046_gate": "BLOCKED_REAL_NON_REGRESSION_NOT_COMPUTED",
            "t1110_gate": "BLOCKED_REAL_NON_REGRESSION_NOT_COMPUTED",
            # Bounded aggregate evidence for downstream fail-closed voting.
            # These are not labels and do not reveal raw commands, usernames,
            # endpoints, payloads, or packet contents.
            "feature_gate_summary": {
                "transfer_tool_command_count": values[FEATURE_ORDER.index("transfer_tool_command_count")],
                "network_connection_count": values[FEATURE_ORDER.index("network_connection_count")],
                "network_established_connection_count": values[FEATURE_ORDER.index("network_established_connection_count")],
                "auth_attempt_count": values[FEATURE_ORDER.index("auth_attempt_count")],
                "auth_telemetry_complete": True,
            },
            "outputs": outputs,
        }
    except (ShadowRuntimeError, OverflowError, ValueError) as exc:
        return _unavailable(str(exc), model)
