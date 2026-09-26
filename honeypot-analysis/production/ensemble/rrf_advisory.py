"""Evidence-gated RRF review ordering for Model1 candidates.

This projection is advisory only.  It never creates a candidate from Model2,
never subtracts an ABSENT result, and never interprets a score as probability
or confidence.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Mapping

from production.ensemble.evidence import (
    MODEL2_UNIFIED54_ARTIFACT_SHA256,
    MODEL2_UNIFIED54_FEATURE_CONTRACT_SHA256,
    MODEL2_UNIFIED54_VERSION,
    MODEL2_V5_SHADOW_STATUS,
)


SCHEMA = "session_ttp_rrf_advisory.v1"
K = 60
MODEL1_WEIGHT = 1.0
MODEL2_WEIGHT = 0.25
TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
SUPPORTED_HEADS = frozenset({"T1105", "T1046", "T1110"})
CAPTURE_CONTRACT = "OUTCOME_INDEPENDENT_FIXED_SESSION_WINDOW_V1"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _object(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _instant(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _model2_gate(
    *, session_id: str, ensemble: Mapping[str, Any],
    session_ended: bool, latest_event_at: str,
) -> str | None:
    if _text(ensemble.get("session_id")) != session_id:
        return "ensemble_session_mismatch"
    model2 = _object(ensemble.get("model2"))
    if model2.get("available") is not True:
        return "model2_unavailable"
    if model2.get("status") != MODEL2_V5_SHADOW_STATUS:
        return "model2_status_unqualified"
    if (
        model2.get("model_version") != MODEL2_UNIFIED54_VERSION
        or model2.get("artifact_sha256") != MODEL2_UNIFIED54_ARTIFACT_SHA256
        or model2.get("feature_contract_sha256") != MODEL2_UNIFIED54_FEATURE_CONTRACT_SHA256
        or model2.get("quality_status") != "CONTROLLED_SYNTHETIC_POC_NOT_REAL_WORLD_ACCURACY"
        or model2.get("capture_selection") != CAPTURE_CONTRACT
    ):
        return "model2_identity_or_capture_unqualified"
    if (
        model2.get("one_model") is not True
        or model2.get("one_inference_call") is not True
        or model2.get("independent_binary_heads") is not True
        or model2.get("argmax_used") is not False
    ):
        return "model2_architecture_unqualified"
    binding = _object(model2.get("binding"))
    if _text(binding.get("session_id")) != session_id:
        return "model2_binding_mismatch"
    for name in ("run_id", "measurement_id", "episode_id"):
        bound = _text(binding.get(name))
        actual = _text(ensemble.get(name) if name == "run_id" else model2.get(name))
        if not bound or bound != actual:
            return "model2_binding_mismatch"
    if not session_ended:
        available = _instant(model2.get("available_at"))
        latest = _instant(latest_event_at)
        if available is None or latest is None or available < latest:
            return "active_session_result_stale"
    return None


def build_rrf_advisory(
    model1_advisory: Mapping[str, Any], ensemble: Mapping[str, Any] | None,
    *, session_id: str, session_ended: bool, latest_event_at: str = "",
) -> dict[str, Any]:
    """Rank only Model1 candidates with an optional gated Model2 rank-1 vote."""
    if (
        _text(model1_advisory.get("session_id")) != session_id
        or model1_advisory.get("schema_version") != "session_model1_ttp_advisory.v1"
        or model1_advisory.get("authority") != "ADVISORY_ONLY"
    ):
        raise ValueError("invalid_model1_session_advisory")
    raw = model1_advisory.get("techniques")
    if not isinstance(raw, list):
        raise ValueError("model1_techniques_required")
    baseline: list[str] = []
    support: dict[str, int] = {}
    for item in raw:
        if not isinstance(item, Mapping):
            raise ValueError("invalid_model1_technique")
        technique = _text(item.get("technique_id"))
        count = item.get("supporting_command_events")
        if (
            not TECHNIQUE.fullmatch(technique)
            or technique in support
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
            or item.get("rank") != len(baseline) + 1
        ):
            raise ValueError("invalid_model1_rank_or_support")
        baseline.append(technique)
        support[technique] = count

    evidence = _object(ensemble)
    global_reason = _model2_gate(
        session_id=session_id,
        ensemble=evidence,
        session_ended=session_ended,
        latest_event_at=latest_event_at,
    )
    model2 = _object(evidence.get("model2"))
    results = evidence.get("results")
    comparisons = {
        _text(row.get("technique_id")): row
        for row in results if isinstance(row, Mapping)
    } if isinstance(results, list) else {}

    rows: list[dict[str, Any]] = []
    any_support = False
    for baseline_rank, technique in enumerate(baseline, start=1):
        comparison = _object(comparisons.get(technique))
        reason = global_reason
        if technique not in SUPPORTED_HEADS:
            reason = "model2_unsupported_technique"
        elif reason is None and technique == "T1105" and model2.get("t1105_transfer_observed") is not True:
            reason = "t1105_session_bound_transfer_evidence_required"
        elif reason is None and technique == "T1046" and comparison.get("model2_available") is not True:
            reason = _text(comparison.get("model2_unavailable_reason")) or "t1046_exact_pcap_zeek_observation_required"
        elif reason is None and technique == "T1110" and model2.get("auth_binding") != "PASS":
            reason = "t1110_auth_binding_required"
        elif reason is None and (
            comparison.get("model2_available") is not True
            or comparison.get("model2_result") not in {"PRESENT", "ABSENT"}
        ):
            reason = "model2_head_unavailable"

        decision = comparison.get("model2_result") if reason is None else None
        supported = decision == "PRESENT"
        base_score = MODEL1_WEIGHT / (K + baseline_rank)
        bonus = MODEL2_WEIGHT / (K + 1) if supported else 0.0
        any_support = any_support or supported
        rows.append({
            "technique_id": technique,
            "baseline_rank": baseline_rank,
            "recommendation_rank": baseline_rank,
            "supporting_command_events": support[technique],
            "model1_rrf_component": base_score,
            "model2_decision": decision,
            "model2_support_added": supported,
            "model2_rrf_component": bonus,
            "rrf_score": base_score + bonus,
            "eligible": reason is None,
            "exclusion_reason": reason,
        })

    ordered_rows = sorted(rows, key=lambda row: (-row["rrf_score"], row["baseline_rank"]))
    for rank, row in enumerate(ordered_rows, start=1):
        row["recommendation_rank"] = rank
    order = [row["technique_id"] for row in ordered_rows]
    return {
        "schema_version": SCHEMA,
        "session_id": session_id,
        "method": "evidence_gated_reciprocal_rank_fusion",
        "method_version": "1",
        "k": K,
        "weights": {"model1": MODEL1_WEIGHT, "model2": MODEL2_WEIGHT},
        "formula": "1/(60+Model1_rank) + 0.25/(60+1) when gated Model2=PRESENT",
        "authority": "ADVISORY_ONLY_EXPERIMENTAL_POC",
        "score_semantics": "RRF_RANK_SCORE_NOT_PROBABILITY_OR_CONFIDENCE",
        "candidate_set_source": "MODEL1_ONLY",
        "negative_vote_policy": "MODEL2_ABSENT_DOES_NOT_SUBTRACT",
        "status": "EXPERIMENTAL_RRF" if any_support else "MODEL1_ONLY",
        "baseline_order": baseline,
        "recommendation_order": order,
        "ordering_changed": order != baseline,
        "model2_support_count": sum(row["model2_support_added"] for row in rows),
        "rows": ordered_rows,
        "model2_artifact_sha256": _text(model2.get("artifact_sha256")) if any_support else "",
        "fallback_reason": global_reason if not any_support else None,
    }


def with_rrf_advisory(
    model1_advisory: Mapping[str, Any], ensemble: Mapping[str, Any] | None,
    *, session_id: str, session_ended: bool, latest_event_at: str = "",
) -> dict[str, Any]:
    result = dict(model1_advisory)
    result["rrf_recommendation"] = build_rrf_advisory(
        model1_advisory,
        ensemble,
        session_id=session_id,
        session_ended=session_ended,
        latest_event_at=latest_event_at,
    )
    return result
