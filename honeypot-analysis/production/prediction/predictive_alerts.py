"""Predictive alert policy for realtime next-step hypotheses.

This module turns prediction snapshots into optional alerts. It deliberately
does not change prediction scores; it only decides whether a stored prediction
is important enough to notify operators before the predicted tactic happens.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from production.utils.serialization import stable_id, utc_now


CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

DEFAULT_TACTIC_SEVERITY = {
    "credential-access": "medium",
    "defense-evasion": "medium",
    "command-and-control": "high",
    "persistence": "high",
    "privilege-escalation": "high",
    "lateral-movement": "critical",
    "exfiltration": "critical",
    "impact": "critical",
}

DEFAULT_POLICY = {
    "enabled": True,
    "min_confidence": "medium",
    "min_score": 0.50,
    "min_severity": "high",
    "min_active_scorers": 1,
    "min_supporting_scorers": 1,
    "block_on_coverage_below_minimum": True,
    "max_divergence_ratio": 0.75,
    "block_external_seed_only": True,
    "block_context_only": True,
    "alert_on_session_status": ["active"],
    "max_alerts_per_snapshot": 1,
    "tactic_severity": DEFAULT_TACTIC_SEVERITY,
    "risk_annotation_severity_boost": {
        "enabled": False,
        "min_risk_level": "high",
        "boost_high_to_critical": False,
    },
}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _policy(prediction_policy: Dict[str, Any]) -> Dict[str, Any]:
    configured = prediction_policy.get("predictive_alerts") or {}
    if not isinstance(configured, dict):
        configured = {}
    merged = dict(DEFAULT_POLICY)
    merged.update(configured)
    tactic_severity = dict(DEFAULT_TACTIC_SEVERITY)
    if isinstance(configured.get("tactic_severity"), dict):
        tactic_severity.update(
            {
                str(tactic).strip().lower(): str(severity).strip().lower()
                for tactic, severity in configured["tactic_severity"].items()
                if str(tactic).strip()
            }
        )
    merged["tactic_severity"] = tactic_severity
    return merged


def _confidence_rank(value: Any) -> int:
    return CONFIDENCE_ORDER.get(str(value or "").strip().lower(), 0)


def _severity_rank(value: Any) -> int:
    return SEVERITY_ORDER.get(str(value or "").strip().lower(), 0)


def _risk_level_rank(value: Any) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3}.get(
        str(value or "").strip().lower(),
        0,
    )


def _float_value(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _severity_with_risk_annotation(
    base_severity: str,
    risk_annotation: Dict[str, Any],
    policy: Dict[str, Any],
) -> Tuple[str, Dict[str, Any]]:
    """Apply contextual risk only to alert severity, never prediction score."""

    risk_policy = policy.get("risk_annotation_severity_boost") or {}
    if not isinstance(risk_policy, dict):
        risk_policy = {}
    meta = {
        "applied": False,
        "base_severity": base_severity,
        "final_severity": base_severity,
        "risk_level": str((risk_annotation or {}).get("level") or "none"),
    }
    if not bool(risk_policy.get("enabled", True)):
        meta["reason"] = "risk annotation severity boost disabled"
        return base_severity, meta
    if not isinstance(risk_annotation, dict) or not bool(risk_annotation.get("active")):
        meta["reason"] = "no active risk annotation"
        return base_severity, meta

    min_risk = str(risk_policy.get("min_risk_level") or "high").strip().lower()
    risk_level = str(risk_annotation.get("level") or "none").strip().lower()
    if _risk_level_rank(risk_level) < _risk_level_rank(min_risk):
        meta["reason"] = f"risk level {risk_level} is below severity boost minimum {min_risk}"
        return base_severity, meta

    severity = base_severity
    if _severity_rank(base_severity) >= _severity_rank("high") and bool(risk_policy.get("boost_high_to_critical", False)):
        severity = "critical"
    elif _severity_rank(base_severity) < _severity_rank("high"):
        severity = "high"

    meta.update(
        {
            "applied": severity != base_severity,
            "final_severity": severity,
            "reason": "active vulnerability context adjusted alert severity",
            "risk_score": risk_annotation.get("score", 0.0),
        }
    )
    return severity, meta


def evaluate_predictive_alert(
    snapshot: Dict[str, Any],
    prediction_policy: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """Return an alert payload and an auditable evaluation block.

    The alert is deduplicated by session + predicted tactic + severity. The
    evaluation block is safe to store inside the prediction snapshot even when
    no alert is created.
    """
    policy = _policy(prediction_policy)
    evaluation: Dict[str, Any] = {
        "schema_version": "predictive_alert_evaluation.v1",
        "enabled": bool(policy.get("enabled", True)),
        "status": "not_triggered",
        "reason": "",
        "policy": {
            "min_confidence": policy.get("min_confidence"),
            "min_score": policy.get("min_score"),
            "min_severity": policy.get("min_severity"),
            "min_active_scorers": policy.get("min_active_scorers"),
            "min_supporting_scorers": policy.get("min_supporting_scorers"),
            "block_on_coverage_below_minimum": policy.get("block_on_coverage_below_minimum"),
            "max_divergence_ratio": policy.get("max_divergence_ratio"),
            "block_external_seed_only": policy.get("block_external_seed_only"),
            "block_context_only": policy.get("block_context_only"),
            "alert_on_session_status": policy.get("alert_on_session_status"),
            "risk_annotation_severity_boost": policy.get("risk_annotation_severity_boost"),
        },
        "candidate": {},
        "suppressed_reasons": [],
    }
    if not policy.get("enabled", True):
        evaluation["status"] = "disabled"
        evaluation["reason"] = "predictive alerting disabled by policy"
        return None, evaluation

    allowed_statuses = {
        str(item or "").strip().lower()
        for item in _as_list(policy.get("alert_on_session_status"))
        if str(item or "").strip()
    }
    session_status = str(snapshot.get("session_status") or "active").strip().lower()
    if allowed_statuses and session_status not in allowed_statuses:
        evaluation["status"] = "suppressed"
        evaluation["reason"] = f"session_status '{session_status}' is outside predictive alert scope"
        evaluation["suppressed_reasons"].append(evaluation["reason"])
        return None, evaluation

    ranking = [item for item in _as_list(snapshot.get("final_ranking")) if isinstance(item, dict)]
    if not ranking:
        evaluation["status"] = "suppressed"
        evaluation["reason"] = "prediction snapshot has no ranked hypotheses"
        evaluation["suppressed_reasons"].append(evaluation["reason"])
        return None, evaluation

    coverage = snapshot.get("coverage") or {}
    active_scorer_count = int(coverage.get("active_scorer_count") or len(snapshot.get("active_scorers") or []))
    min_active_scorers = int(policy.get("min_active_scorers") or 0)
    if active_scorer_count < min_active_scorers:
        reason = f"active scorer count {active_scorer_count} is below alert minimum {min_active_scorers}"
        evaluation["suppressed_reasons"].append(reason)
        if policy.get("block_on_coverage_below_minimum", True):
            evaluation["status"] = "suppressed"
            evaluation["reason"] = reason
            return None, evaluation

    if bool(coverage.get("below_minimum")) and policy.get("block_on_coverage_below_minimum", True):
        reason = coverage.get("reason") or "prediction coverage is below configured minimum"
        evaluation["status"] = "suppressed"
        evaluation["reason"] = reason
        evaluation["suppressed_reasons"].append(str(reason))
        return None, evaluation

    agreement = snapshot.get("agreement") or {}
    divergence_ratio = _float_value(agreement.get("divergence_ratio"), 0.0)
    max_divergence = _float_value(policy.get("max_divergence_ratio"), 1.0)
    if divergence_ratio > max_divergence:
        reason = f"scorer divergence ratio {divergence_ratio} exceeds alert maximum {max_divergence}"
        evaluation["status"] = "suppressed"
        evaluation["reason"] = reason
        evaluation["suppressed_reasons"].append(reason)
        return None, evaluation

    min_confidence = str(policy.get("min_confidence") or "medium").strip().lower()
    min_score = _float_value(policy.get("min_score"), 0.0)
    min_severity = str(policy.get("min_severity") or "high").strip().lower()
    severity_by_tactic = policy.get("tactic_severity") or {}
    max_alerts = max(int(policy.get("max_alerts_per_snapshot") or 1), 1)

    selected: Optional[Dict[str, Any]] = None
    for item in ranking:
        tactic = str(item.get("tactic") or "").strip().lower()
        if not tactic:
            evaluation["suppressed_reasons"].append("ranked item has no tactic")
            continue
        base_severity = str(severity_by_tactic.get(tactic) or "info").strip().lower()
        severity, risk_severity_meta = _severity_with_risk_annotation(
            base_severity,
            snapshot.get("risk_annotation") or {},
            policy,
        )
        confidence = str(item.get("confidence") or "").strip().lower()
        score = _float_value(item.get("calibrated_score", item.get("score")), 0.0)
        support = item.get("support") or {}
        if not isinstance(support, dict):
            support = {}
        supporting_scorer_count = int(support.get("supporting_scorer_count") or len(item.get("sources") or []))
        candidate = {
            "predicted_tactic": tactic,
            "severity": severity,
            "base_severity": base_severity,
            "confidence": confidence,
            "score": round(score, 4),
            "snapshot_rank": ranking.index(item) + 1,
            "supporting_scorer_count": supporting_scorer_count,
            "supporting_scorers": support.get("supporting_scorers") or [],
            "dominant_source": support.get("dominant_source") or "",
            "external_seed_only": bool(support.get("external_seed_only")),
            "context_only": bool(support.get("context_only") or support.get("context_or_risk_only")),
            "risk_annotation": snapshot.get("risk_annotation") or {},
            "risk_severity_adjustment": risk_severity_meta,
        }
        evaluation["candidate"] = candidate
        min_supporting_scorers = int(policy.get("min_supporting_scorers") or 0)
        if supporting_scorer_count < min_supporting_scorers:
            evaluation["suppressed_reasons"].append(
                f"{tactic} has {supporting_scorer_count} supporting scorer(s); alert minimum is {min_supporting_scorers}"
            )
            continue
        if candidate["external_seed_only"] and policy.get("block_external_seed_only", True):
            evaluation["suppressed_reasons"].append(
                f"{tactic} is supported only by external seed prior evidence"
            )
            continue
        if candidate["context_only"] and policy.get("block_context_only", True):
            evaluation["suppressed_reasons"].append(
                f"{tactic} is supported only by enrichment/risk context"
            )
            continue
        if _severity_rank(severity) < _severity_rank(min_severity):
            evaluation["suppressed_reasons"].append(
                f"{tactic} severity {severity} is below alert minimum {min_severity}"
            )
            continue
        if _confidence_rank(confidence) < _confidence_rank(min_confidence):
            evaluation["suppressed_reasons"].append(
                f"{tactic} confidence {confidence or 'unknown'} is below alert minimum {min_confidence}"
            )
            continue
        if score < min_score:
            evaluation["suppressed_reasons"].append(
                f"{tactic} score {score:.4f} is below alert minimum {min_score:.4f}"
            )
            continue
        selected = {**candidate, "ranking_item": item}
        break

    if not selected:
        evaluation["status"] = "suppressed"
        evaluation["reason"] = evaluation["suppressed_reasons"][-1] if evaluation["suppressed_reasons"] else "no hypothesis crossed alert thresholds"
        return None, evaluation

    ranking_item = selected["ranking_item"]
    session_id = str(snapshot.get("session_id") or "unknown")
    policy_metadata = prediction_policy.get("policy_metadata") or {}
    policy_id = str(policy_metadata.get("policy_id") or policy_metadata.get("source") or "inline")
    alert_id = stable_id(
        "predalert",
        {
            "session_id": session_id,
            "predicted_tactic": selected["predicted_tactic"],
            "severity": selected["severity"],
            "policy_id": policy_id,
        },
    )
    reasons = [str(reason) for reason in ranking_item.get("reasons") or [] if str(reason)]
    reason = (
        f"Predicted next tactic '{selected['predicted_tactic']}' crossed predictive alert policy "
        f"({selected['confidence']} confidence, score={selected['score']}, severity={selected['severity']})."
    )
    alert = {
        "alert_id": alert_id,
        "alert_type": "predictive_next_step",
        "session_id": session_id,
        "severity": str(selected["severity"]).upper(),
        "reason": reason,
        "created_at": utc_now(),
        "src_ip": snapshot.get("src_ip") or "unknown",
        "predicted_tactic": selected["predicted_tactic"],
        "predicted_confidence": selected["confidence"],
        "predicted_score": selected["score"],
        "snapshot_id": snapshot.get("snapshot_id") or "",
        "event_id": snapshot.get("event_id") or "",
        "payload": {
            "alert_type": "predictive_next_step",
            "policy_id": policy_id,
            "snapshot_id": snapshot.get("snapshot_id") or "",
            "session_status": snapshot.get("session_status") or "",
            "predicted_tactic": selected["predicted_tactic"],
            "predicted_confidence": selected["confidence"],
            "predicted_score": selected["score"],
            "predicted_severity": selected["severity"],
            "rank": selected["snapshot_rank"],
            "reasons": reasons[:8],
            "sources": ranking_item.get("sources") or [],
            "trust_status": snapshot.get("trust_status") or {},
            "coverage": snapshot.get("coverage") or {},
            "agreement": snapshot.get("agreement") or {},
            "classification_quality": snapshot.get("classification_quality") or {},
            "risk_annotation": snapshot.get("risk_annotation") or {},
            "risk_severity_adjustment": selected.get("risk_severity_adjustment") or {},
        },
    }
    evaluation.update(
        {
            "status": "alert_created",
            "reason": reason,
            "alert_id": alert_id,
            "candidate": {
                key: value for key, value in selected.items() if key != "ranking_item"
            },
        }
    )
    if max_alerts <= 1:
        return alert, evaluation
    return alert, evaluation
