"""Canonical new-report coordinator.

This module is the only production bridge from reconstructed session state to
``session_assessment.v4``.  It deliberately contains no v1/v2/v3 report
generator, attacker-intent field, score, next-action prediction, recommendation
engine, response execution, alert authority, or LLM client.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Optional

from production.reporting.session_assessment_v4 import build_session_assessment_v4
from production.utils.sensitive_data import redact_for_artifact


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _correlation_evidence(item: Dict[str, Any]) -> List[str]:
    summaries: List[str] = []
    reason = _clean(item.get("reason"))
    if reason:
        summaries.append(reason[:240])
    for result in item.get("matched_conditions") or []:
        if not isinstance(result, dict):
            continue
        description = _clean(result.get("description"))
        if description:
            summaries.append(description[:240])
    return list(dict.fromkeys(summaries))[:8]


def build_session_correlation_hunting_context(
    session_correlations: Optional[Iterable[Dict[str, Any]]] = None,
    session_id: str = "",
) -> Dict[str, Any]:
    """Expose correlations as non-authoritative hunting context."""

    findings: List[Dict[str, Any]] = []
    source_counts: Counter[str] = Counter()
    tactic_counts: Counter[str] = Counter()
    for item in session_correlations or []:
        if not isinstance(item, dict):
            continue
        main_ttp = _clean(item.get("ttp"))
        tactic = _clean(item.get("tactic"))
        source_type = _clean(item.get("source_type"))
        if source_type:
            source_counts[source_type] += 1
        if tactic:
            tactic_counts[tactic] += 1
        findings.append(
            {
                "session_id": _clean(item.get("session_id"))
                or session_id
                or "unknown",
                "correlation_id": _clean(item.get("correlation_id")),
                "rule_id": _clean(item.get("rule_id")),
                "correlation_rule_fired": _clean(item.get("rule_id")),
                "predicted_technique": {
                    "main_ttp": main_ttp,
                    "technique_name": _clean(item.get("technique_name"))
                    or main_ttp,
                    "tactic": tactic,
                },
                "main_ttp": main_ttp,
                "source_ttp": _clean(item.get("source_ttp")) or main_ttp,
                "source_subtechnique": _clean(item.get("source_subtechnique")),
                "technique_granularity": _clean(
                    item.get("technique_granularity")
                )
                or "parent",
                "source_type": source_type,
                "confidence": item.get("confidence"),
                "evidence_type": _clean(item.get("evidence_type")),
                "temporal_claim": bool(item.get("temporal_claim", False)),
                "apply_to_prediction": False,
                "reason": _clean(item.get("reason")),
                "evidence": _correlation_evidence(item),
                "matched_conditions": deepcopy(
                    item.get("matched_conditions") or []
                ),
                "references": deepcopy(item.get("references") or []),
                "provenance": deepcopy(item.get("provenance") or {}),
            }
        )

    return {
        "schema_version": "session_threat_hunting_context.v1",
        "session_id": session_id
        or (findings[0]["session_id"] if findings else "unknown"),
        "status": "available" if findings else "not_available",
        "interpretation": (
            "Session correlations are non-authoritative post-session hunting "
            "context and cannot change canonical findings or hypotheses."
        ),
        "correlation_count": len(findings),
        "correlation_rules_fired": [
            item["rule_id"] for item in findings if item.get("rule_id")
        ],
        "main_ttps": sorted(
            {item["main_ttp"] for item in findings if item.get("main_ttp")}
        ),
        "source_type_counts": dict(sorted(source_counts.items())),
        "tactic_counts": dict(sorted(tactic_counts.items())),
        "session_correlations": findings,
    }


class CanonicalAssessmentCoordinator:
    """Build exactly one deterministic v4 assessment for a closed session."""

    def __init__(
        self,
        *,
        behavior_policy_document: Optional[Dict[str, Any]] = None,
        behavior_policy_path: str = "",
        classification_policy: Optional[Dict[str, Any]] = None,
        classification_rules_path: str = "",
        prediction_policy: Optional[Dict[str, Any]] = None,
        prediction_policy_path: str = "",
        prediction_context: Optional[Dict[str, Any]] = None,
        response_guidance_policy_path: str = "",
        response_guidance_asset_profile_path: str = "",
        mitre_cache_path: str = "",
    ) -> None:
        self.behavior_policy_document = deepcopy(behavior_policy_document)
        self.behavior_policy_path = _clean(behavior_policy_path)
        self.classification_policy = deepcopy(classification_policy or {})
        self.classification_rules_path = _clean(classification_rules_path)
        self.prediction_policy = deepcopy(prediction_policy)
        self.prediction_policy_path = _clean(prediction_policy_path)
        self.prediction_context = deepcopy(prediction_context or {})
        self.response_guidance_policy_path = _clean(
            response_guidance_policy_path
        )
        self.response_guidance_asset_profile_path = _clean(
            response_guidance_asset_profile_path
        )
        self.mitre_cache_path = _clean(mitre_cache_path)

    async def analyze(
        self,
        _ioc_bundle: Any,
        _tactic_summary: Dict[str, List[str]],
        sessions: List[Any],
        _bpg_list: List[Dict[str, Any]],
        *,
        ttp_command_map: Optional[Dict[str, List[str]]] = None,
        raw_events: Optional[List[Dict[str, Any]]] = None,
        session_correlations: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        del ttp_command_map
        report = build_session_assessment_v4(
            sessions,
            raw_events=raw_events or [],
            behavior_policy_document=self.behavior_policy_document,
            behavior_policy_path=self.behavior_policy_path,
            classification_policy=self.classification_policy,
            classification_policy_path=self.classification_rules_path,
            model_artifact_provenance=self.prediction_policy,
            prediction_context=self.prediction_context,
            correlation_context=session_correlations or [],
            mitre_cache_path=self.mitre_cache_path,
            response_guidance_policy_path=self.response_guidance_policy_path,
            response_guidance_asset_profile_path=(
                self.response_guidance_asset_profile_path
            ),
        )
        redacted = redact_for_artifact(report)
        if not isinstance(redacted, dict):
            raise TypeError("canonical report redaction must return an object")
        return redacted
