"""Explicit, manifest-bound hard-backoff VOMM rollback predictor.

This module is intentionally narrow.  It contains no local learning, weighted
scorers, heuristic fallback, routing, alert generation, or automatic policy
transition.  It is reached only when an operator explicitly selects the
validated ``external_hard_backoff_vomm`` rollback policy.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

from production.correlation.session_ttp_knowledge import main_ttp_id
from production.utils.serialization import stable_id, utc_now


MODE = "external_hard_backoff_vomm"
SNAPSHOT_SCHEMA_VERSION = "prediction_snapshot.v2"


def empty_transition_model() -> Dict[str, Any]:
    """Return the fail-closed model used when the pinned artifact is invalid."""

    return {
        "schema_version": "external_transition_model.v1",
        "model_id": "",
        "usable_sessions": 0,
        "transition_count": 0.0,
        "prefix_transition_count": 0.0,
        "technique_transition_count": 0.0,
        "prefix_max_length": 3,
        "transitions": {},
        "prefix_transitions": {},
        "technique_transitions": {},
        "technique_tactics": {},
        "start_counts": {},
        "provenance": {},
    }


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _confidence(score: float) -> str:
    if score >= 0.70:
        return "high"
    if score >= 0.40:
        return "medium"
    return "low"


def _support_level(count: float, total: float, minimum: float) -> str:
    if total <= 0 or count <= 0:
        return "none"
    if count >= 100 or total >= 500:
        return "high"
    if count >= 20 or total >= 100:
        return "medium"
    return "low" if count >= max(minimum, 1) else "below_minimum"


def _artifact_metadata(
    model: Mapping[str, Any],
    validation: Mapping[str, Any],
) -> Dict[str, Any]:
    provenance = model.get("provenance") or {}
    manifest = validation.get("manifest") if isinstance(validation.get("manifest"), dict) else {}
    artifact = manifest.get("artifact") if isinstance(manifest.get("artifact"), dict) else {}
    return {
        "status": str(validation.get("status") or "unavailable"),
        "valid": bool(validation.get("valid")),
        "reasons": [str(reason) for reason in validation.get("reasons") or []],
        "model_id": str(validation.get("model_id") or model.get("model_id") or ""),
        "manifest_id": str(
            validation.get("manifest_id") or provenance.get("manifest_id") or ""
        ),
        "artifact_version": str(
            validation.get("artifact_version") or model.get("artifact_version") or ""
        ),
        "artifact_sha256": str(
            validation.get("actual_artifact_sha256")
            or validation.get("actual_sha256")
            or artifact.get("sha256")
            or ""
        ),
        "manifest_sha256": str(validation.get("manifest_sha256") or ""),
        "schema_version": str(model.get("schema_version") or ""),
        "source": MODE,
    }


def _supported_counts(
    model: Mapping[str, Any],
    features: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> tuple[Dict[str, Any], str, str, float]:
    """Return the first supported prefix, technique, or tactic count vector."""

    sequence = [
        str(value or "").strip()
        for value in features.get("tactic_sequence") or []
        if str(value or "").strip()
    ]
    max_prefix = min(
        max(int(policy.get("prefix_max_length") or model.get("prefix_max_length") or 3), 1),
        len(sequence),
    )
    prefix_min = _number(
        policy.get("external_min_prefix_transition_count"),
        _number(policy.get("external_min_transition_count"), 2.0),
    )
    for length in range(max_prefix, 1, -1):
        context = ">".join(sequence[-length:])
        counts = (model.get("prefix_transitions") or {}).get(context) or {}
        total = sum(_number(value) for value in counts.values())
        if total >= prefix_min and counts:
            return dict(counts), "prefix", context, prefix_min

    technique = main_ttp_id(features.get("last_ttp"))
    technique_min = _number(
        policy.get("external_min_technique_transition_count"),
        _number(policy.get("external_min_transition_count"), 2.0),
    )
    if technique:
        counts = (model.get("technique_transitions") or {}).get(technique) or {}
        total = sum(_number(value) for value in counts.values())
        if total >= technique_min and counts:
            return dict(counts), "technique", technique, technique_min

    tactic = str(features.get("last_tactic") or "").strip()
    tactic_min = _number(
        policy.get("external_min_tactic_transition_count"),
        _number(policy.get("external_min_transition_count"), 2.0),
    )
    if tactic:
        counts = (model.get("transitions") or {}).get(tactic) or {}
        total = sum(_number(value) for value in counts.values())
        if total >= tactic_min and counts:
            return dict(counts), "tactic", tactic, tactic_min
    return {}, "", "", 0.0


class ValidatedVommRollbackPredictor:
    """The sole explicit VOMM rollback implementation."""

    name = "validated_external_hard_backoff_vomm"
    version = "1.0"

    def __init__(
        self,
        policy: Mapping[str, Any],
        *,
        model: Mapping[str, Any] | None = None,
        artifact_validation: Mapping[str, Any] | None = None,
    ) -> None:
        self.policy = dict(policy or {})
        self.model = dict(model or empty_transition_model())
        self.artifact_validation = dict(
            artifact_validation
            or {
                "status": "unavailable",
                "valid": False,
                "reasons": ["external_artifact_validation_not_supplied"],
            }
        )

    @property
    def enabled(self) -> bool:
        return bool(self.policy.get("enabled", True))

    def predict(self, features: Dict[str, Any], event_id: str = "") -> Dict[str, Any]:
        artifact = _artifact_metadata(self.model, self.artifact_validation)
        counts: Dict[str, Any] = {}
        transition_type = ""
        context = ""
        minimum = 0.0
        if artifact["valid"]:
            counts, transition_type, context, minimum = _supported_counts(
                self.model, features, self.policy
            )

        total = sum(_number(value) for value in counts.values())
        smoothing = max(
            _number(self.policy.get("transition_smoothing"), _number(self.model.get("smoothing"), 0.05)),
            0.0,
        )
        denominator = total + smoothing * max(len(counts), 1)
        technique_tactics = self.model.get("technique_tactics") or {}
        min_score = max(
            _number(
                (self.policy.get("primary_transition") or {}).get("min_transition_score"),
                _number(self.policy.get("min_score"), 0.01),
            ),
            0.0,
        )
        ranking = []
        for target, raw_count in sorted(
            counts.items(), key=lambda item: _number(item[1]), reverse=True
        ):
            count = _number(raw_count)
            score = (count + smoothing) / denominator if denominator else 0.0
            if score < min_score:
                continue
            tactic = (
                str(technique_tactics.get(str(target)) or "")
                if transition_type == "technique"
                else str(target)
            )
            if not tactic:
                continue
            support = _support_level(count, total, minimum)
            source = {
                "name": "external_seed_transition",
                "version": "1.0",
                "source_type": str(
                    self.model.get("source_type") or "external_cowrie_seed"
                ),
                "configured_weight": 0.0,
                "effective_weight": 1.0,
                "normalized_weight": 1.0,
                "raw_score": round(score, 4),
                "adjusted_score": round(score, 4),
                "weighted_score": round(score, 4),
                "weighting_method": "external_hard_backoff_no_ensemble",
                "damped_by_classification_confidence": False,
                "damping_factor": 1.0,
                "evidence_sources": [
                    str(
                        (self.model.get("provenance") or {}).get("dataset_handle")
                        or "manifest-bound external Cowrie dataset"
                    )
                ],
                "references": [],
                "metadata": {
                    "model_id": self.model.get("model_id", ""),
                    "transition_count": round(total, 4),
                    "transition_support": round(count, 4),
                    "transition_probability": round(score, 4),
                    "transition_support_level": support,
                    "transition_total": round(total, 4),
                    "support_share": round(count / total, 4) if total else 0.0,
                    "min_support": minimum,
                    "transition_type": transition_type,
                    "transition_context": context,
                    "training_source": str(
                        (self.model.get("provenance") or {}).get("training_source")
                        or "manifest-bound external transition counts"
                    ),
                    "provenance": dict(self.model.get("provenance") or {}),
                    "temporal_claim": True,
                },
            }
            ranking.append(
                {
                    "tactic": tactic,
                    "score": round(score, 4),
                    "calibrated_score": round(score, 4),
                    "calibration": {"applied": False},
                    "confidence": _confidence(score),
                    "coverage_below_minimum": False,
                    "reasons": [
                        f"manifest-bound external history supports {tactic} from {context}"
                    ],
                    "sources": [source],
                    "source_types": [source["source_type"]],
                    "support": {
                        "supporting_scorer_count": 1,
                        "supporting_scorers": ["external_seed_transition"],
                        "external_seed_support": True,
                        "external_seed_only": True,
                        "local_support": False,
                        "dominant_source": "external_seed_transition",
                    },
                }
            )
        ranking = ranking[: max(int(self.policy.get("max_hypotheses") or 5), 1)]

        if not artifact["valid"]:
            status = "model_unavailable"
            reason = "; ".join(artifact["reasons"]) or "external artifact is unavailable"
        elif not ranking:
            status = "abstained"
            reason = "no empirically supported external hard-backoff context"
        else:
            status = "predicted"
            reason = "external hard-backoff context is empirically supported"

        snapshot: Dict[str, Any] = {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "engine": {"name": self.name, "version": self.version},
            "prediction_mode": MODE,
            "prediction_status": status,
            "prediction_status_reason": reason,
            "primary_model": MODE,
            "source": "external_seed_transition",
            "fallback_used": False,
            "fallback_reason": "",
            "transition_evidence_type": transition_type if ranking else "",
            "transition_context": context if ranking else "",
            "transition_count": round(total, 4) if ranking else 0.0,
            "evidence_count": (
                round(_number((ranking[0]["sources"][0]["metadata"]).get("transition_support")), 4)
                if ranking
                else 0.0
            ),
            "session_id": features.get("session_id", "unknown"),
            "src_ip": features.get("src_ip", "unknown"),
            "session_status": features.get("status", "active"),
            "event_id": event_id,
            "features_hash": features.get("features_hash") or stable_id("features", features),
            "generated_at": utc_now(),
            "external_artifact": artifact,
            "coverage": {
                "active_scorer_count": 1 if ranking else 0,
                "min_active_scorers": 1,
                "below_minimum": not bool(ranking),
                "reason": "" if ranking else reason,
            },
            "active_scorers": ["external_seed_transition"] if ranking else [],
            "active_weights": {"external_seed_transition": 1.0} if ranking else {},
            "weights": {},
            "effective_weights": {},
            "weight_influence_scope": "not_applicable_external_authority",
            "ranking_influence": {
                "production_mode": MODE,
                "production_effective_scorers": (
                    ["external_seed_transition"] if ranking else []
                ),
                "local_transition": "not_computed",
                "heuristic_prior": "not_computed",
                "enrichment_context": "not_authoritative",
                "weighted_ensemble": "not_computed",
            },
            "calibration_status": {
                "enabled": False,
                "method": "not_probability_calibrated",
            },
            "trust_status": {
                "status": "review_required",
                "evidence_posture": (
                    "external_immutable_authoritative"
                    if ranking
                    else "external_immutable_unavailable_or_abstained"
                ),
                "warnings": [
                    "External hard-backoff scores are not probability-calibrated."
                ],
            },
            "primary_transition": {
                "primary_model": MODE,
                "selected_source": "external_seed_transition" if ranking else "",
                "source_order": ["external_seed_transition"],
                "fallback_scorer": "",
                "fallback_used": False,
                "fallback_reason": "",
                "transition_evidence_type": transition_type if ranking else "",
                "transition_context": context if ranking else "",
                "transition_count": round(total, 4) if ranking else 0.0,
                "evidence_count": (
                    round(_number(ranking[0]["sources"][0]["metadata"].get("transition_support")), 4)
                    if ranking
                    else 0.0
                ),
            },
            "local_shadow_prediction": {
                "schema_version": "local_transition_shadow.v1",
                "authority": "removed",
                "not_authoritative": True,
                "status": "not_computed",
                "ranking": [],
                "reason": "Local-transition scoring is not part of the supported repository.",
            },
            "generic_progression_prior": {
                "schema_version": "generic_progression_prior.v1",
                "source": "none",
                "not_empirical_prediction": True,
                "not_authoritative": True,
                "not_for_alerts": True,
                "not_for_hypotheses": True,
                "not_for_response_guidance": True,
                "not_for_action_eligibility": True,
                "tactics": [],
                "reason": "Heuristic progression is not computed by the supported runtime.",
            },
            "risk_annotation": {
                "active": False,
                "ranking_influence": "none",
                "annotations": [],
                "reasons": [],
            },
            "scorer_outputs": {
                "external_seed_transition": [
                    {
                        "tactic": item["tactic"],
                        "score": item["score"],
                        "source": "external_seed_transition",
                    }
                    for item in ranking
                ]
            },
            "final_ranking": ranking,
            "prediction": [item["tactic"] for item in ranking],
        }
        snapshot["snapshot_id"] = stable_id(
            "predsnap",
            {
                "schema_version": snapshot["schema_version"],
                "session_id": snapshot["session_id"],
                "event_id": event_id,
                "features_hash": snapshot["features_hash"],
                "prediction_status": status,
                "artifact_sha256": artifact["artifact_sha256"],
                "ranking": ranking,
            },
        )
        return snapshot
