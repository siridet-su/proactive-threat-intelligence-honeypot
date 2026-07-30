"""Asynchronous closed-session analysis worker."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import json
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type

from production.classification.trust import (
    classification_audit_reason,
    is_trusted_classification_event,
)
from production.reporting.canonical_pipeline import (
    CanonicalAssessmentCoordinator,
    build_session_correlation_hunting_context,
)
from production.enrichment.mitre_attack_loader import load_mitre_attack_db
from production.workers.session_monitor import SessionState, build_pipeline_trigger
from production.enrichment.threat_feed_loader import load_threat_feeds

from production.reporting.actor_attribution import enrich_report_with_actor_attribution
from production.reporting.analysis_policy import session_analysis_skip_reason
from production.reporting.artifacts import attach_report_artifacts
from production.policies.threat_hypothesis_behavior_policy import load_behavior_policy
from production.reporting.session_assessment_v4 import (
    SessionAssessmentV4Error,
    build_session_assessment_v4,
    canonical_assessment_id,
    validate_session_assessment_v4,
)
from production.utils.credential_hmac import credential_metadata_for_provenance
from production.utils.config import ProductionConfig
from production.enrichment.enrichment_cache import load_combined_ip_enrichment
from production.enrichment.feed_status import collect_feed_status, save_feed_status
from production.utils.runtime_context import attach_runtime_context
from production.utils.sensitive_data import (
    redact_error_for_log,
    redact_exception_for_log,
    redact_for_artifact,
    redact_for_log,
)
from production.utils.serialization import command_observation_provenance, utc_now
from production.utils.service_lifecycle import ServiceLifecycle
from production.utils.http_security import safe_correlation_id
from production.storage import open_storage
from production.workers.job_lifecycle import (
    JobLeaseHeartbeat,
    job_failure_identity,
    job_retry_delay,
    new_job_owner,
)


def _safe_exception_text(exc: BaseException) -> str:
    return redact_exception_for_log(exc)


def _safe_error_text(value: Any) -> str:
    return redact_error_for_log(value)


def _safe_log_json(value: Any) -> str:
    try:
        redacted = redact_for_log(value, max_string_chars=1_000)
        if isinstance(redacted, dict) and "error" in redacted:
            redacted = dict(redacted)
            redacted["error"] = redact_error_for_log(redacted["error"])
        return json.dumps(
            redacted,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    except Exception:
        return '{"service": "analysis_worker", "status": "log_redaction_failed"}'


def _safe_report_mapping(value: Any) -> Dict[str, Any]:
    try:
        redacted = redact_for_artifact(value)
    except Exception:
        raise ValueError("report redaction failed") from None
    if not isinstance(redacted, dict):
        raise TypeError("report must redact to an object")
    return redacted


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


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _main_ttp(value: Any) -> str:
    text = _clean_text(value).upper()
    return text.split(".", 1)[0] if "." in text and text.startswith("T") else text


def _average(values: List[float]) -> float:
    return round(sum(values) / len(values), 4) if values else 0.0


def _trusted_payload_views(session_payload: Dict[str, Any]) -> Dict[str, Any]:
    events = [
        event for event in _as_list(session_payload.get("classification_events"))
        if isinstance(event, dict)
    ]
    if not events:
        return {
            "ttps": list(session_payload.get("ttps") or []),
            "tactics": list(session_payload.get("tactics") or []),
            "ttp_command_map": dict(session_payload.get("ttp_command_map") or {}),
        }
    ttps: List[str] = []
    tactics: List[str] = []
    ttp_command_map: Dict[str, List[str]] = {}
    for event in events:
        if not is_trusted_classification_event(event):
            continue
        ttp = _main_ttp(event.get("ttp"))
        tactic = _clean_text(event.get("tactic"))
        command = _clean_text(event.get("command") or event.get("input"))
        if ttp and ttp not in ttps:
            ttps.append(ttp)
        if tactic and tactic != "unknown" and tactic not in tactics:
            tactics.append(tactic)
        if ttp and command:
            commands = ttp_command_map.setdefault(ttp, [])
            if command not in commands:
                commands.append(command)
    return {"ttps": ttps, "tactics": tactics, "ttp_command_map": ttp_command_map}


def _direct_command_ttp_layer(session_payload: Dict[str, Any]) -> Dict[str, Any]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for event in _as_list(session_payload.get("classification_events")):
        if not isinstance(event, dict):
            continue
        if not is_trusted_classification_event(event):
            continue
        raw_ttp = _clean_text(event.get("ttp"))
        if not raw_ttp or raw_ttp == "unknown":
            continue
        main_ttp = _main_ttp(raw_ttp)
        item = grouped.setdefault(
            main_ttp,
            {
                "main_ttp": main_ttp,
                "source_ttp_values": [],
                "tactic": _clean_text(event.get("tactic")),
                "source_type": "direct_command_classification",
                "evidence_type": "command_level_classifier_output",
                "commands": [],
                "sources": [],
                "confidence_values": [],
                "evidence": [],
            },
        )
        source_ttp = _clean_text(event.get("source_ttp") or event.get("source_subtechnique") or raw_ttp)
        if source_ttp and source_ttp not in item["source_ttp_values"]:
            item["source_ttp_values"].append(source_ttp)
        source = _clean_text(event.get("source") or "unknown")
        if source and source not in item["sources"]:
            item["sources"].append(source)
        command = _clean_text(event.get("command") or event.get("input"))
        original_command = _clean_text(event.get("original_command"))
        if command and command not in item["commands"]:
            item["commands"].append(command)
        try:
            confidence = float(event.get("confidence"))
            item["confidence_values"].append(max(0.0, min(1.0, confidence)))
        except (TypeError, ValueError):
            confidence = None
        item["evidence"].append(
            {
                "evidence_id": _clean_text(event.get("evidence_id")),
                "command": command,
                "original_command": original_command,
                "command_outcome": _clean_text(event.get("command_outcome")) or "legacy_outcome_unknown",
                "cowrie_eventid": _clean_text(event.get("cowrie_eventid")),
                "timestamp": _clean_text(event.get("event_timestamp")),
                "source": source,
                "agreement_status": _clean_text(event.get("agreement_status")),
                "confidence": confidence,
                "confidence_semantics": _clean_text(event.get("confidence_semantics")) or "legacy_unscoped_score",
                "rule_policy_id": _clean_text(event.get("rule_policy_id")),
                "rule_policy_version": _clean_text(event.get("rule_policy_version")),
                "subcommand_index": event.get("subcommand_index"),
                "subcommand_count": event.get("subcommand_count"),
                "technique_granularity": event.get("technique_granularity") or "parent",
            }
        )
    items = []
    for item in grouped.values():
        confidences = item.pop("confidence_values", [])
        item["confidence"] = {
            "min": round(min(confidences), 4) if confidences else None,
            "average": _average(confidences) if confidences else None,
            "count": len(confidences),
        }
        item["evidence"] = item["evidence"][:10]
        item["commands"] = item["commands"][:10]
        items.append(item)
    items.sort(key=lambda item: item["main_ttp"])
    return {
        "status": "available" if items else "not_available",
        "count": len(items),
        "description": "Direct command-level TTPs produced by rules and/or SecureBERT.",
        "items": items,
    }


def _audit_only_classification_layer(session_payload: Dict[str, Any]) -> Dict[str, Any]:
    items = []
    for event in _as_list(session_payload.get("classification_events")):
        if not isinstance(event, dict) or is_trusted_classification_event(event):
            continue
        items.append(
            {
                "command": _clean_text(event.get("command") or event.get("input")),
                "candidate_ttp": _clean_text(event.get("ttp")),
                "candidate_tactic": _clean_text(event.get("tactic")),
                "source": _clean_text(event.get("source") or "unknown"),
                "confidence": event.get("confidence"),
                "high_confidence": event.get("high_confidence"),
                "evidence_type": "audit_only_classification_candidate",
                "reason": classification_audit_reason(event),
                "excluded_from_observed_facts": True,
                "excluded_from_prediction": True,
            }
        )
    return {
        "status": "available" if items else "not_available",
        "count": len(items),
        "description": (
            "Weak classifier candidates and shell noise retained for audit only; "
            "they are not observed ATT&CK facts and do not drive prediction or the threat hypothesis."
        ),
        "items": items[:50],
    }


def _session_correlated_ttp_layer(hunting_context: Dict[str, Any]) -> Dict[str, Any]:
    correlations = [
        item
        for item in _as_list(hunting_context.get("session_correlations"))
        if isinstance(item, dict)
    ]
    return {
        "status": "available" if correlations else "not_available",
        "count": len(correlations),
        "description": (
            "Session-level TTPs inferred from the whole session pattern. These are "
            "threat-hunting correlations, not raw command classifications."
        ),
        "correlation_rules_fired": hunting_context.get("correlation_rules_fired") or [],
        "source_type_counts": hunting_context.get("source_type_counts") or {},
        "items": correlations,
    }


def _prediction_hypothesis_layer(prediction_snapshot: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    payload = prediction_snapshot or {}
    if isinstance(payload.get("payload"), dict):
        payload = payload["payload"]
    ranking = [
        item
        for item in _as_list(payload.get("final_ranking"))
        if isinstance(item, dict)
    ]
    items = []
    for item in ranking:
        sources = [
            source
            for source in _as_list(item.get("sources"))
            if isinstance(source, dict)
        ]
        items.append(
            {
                "predicted_tactic": _clean_text(item.get("tactic")),
                "predicted_technique": _clean_text(item.get("technique")),
                "main_ttp": _main_ttp(item.get("technique")),
                "confidence": item.get("confidence"),
                "score": item.get("score"),
                "calibrated_score": item.get("calibrated_score"),
                "source_type": ", ".join(item.get("source_types") or []),
                "source_types": item.get("source_types") or [],
                "evidence_type": "realtime_prediction_hypothesis",
                "reasons": item.get("reasons") or [],
                "sources": sources,
            }
        )
    return {
        "status": "available" if items else "not_available",
        "count": len(items),
        "description": (
            "Realtime next-step hypotheses. These are forecasts only and must not "
            "be mixed into the direct observed TTP list."
        ),
        "snapshot_id": payload.get("snapshot_id") or "",
        "generated_at": payload.get("generated_at") or "",
        "trust_status": payload.get("trust_status") or {},
        "agreement": payload.get("agreement") or {},
        "items": items,
    }


def build_threat_evidence_layers(
    session_payload: Dict[str, Any],
    prediction_snapshot: Optional[Dict[str, Any]] = None,
    hunting_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    hunting = hunting_context or build_session_correlation_hunting_context(
        session_payload.get("session_ttp_correlations", []),
        session_payload.get("session_id", "unknown"),
    )
    direct = _direct_command_ttp_layer(session_payload)
    audit_only = _audit_only_classification_layer(session_payload)
    correlated = _session_correlated_ttp_layer(hunting)
    prediction = _prediction_hypothesis_layer(prediction_snapshot)
    return {
        "schema_version": "threat_evidence_layers.v1",
        "session_id": session_payload.get("session_id", "unknown"),
        "interpretation": (
            "Direct command TTPs, session-correlated TTPs, and realtime prediction "
            "hypotheses are intentionally separated so the report does not mix facts, "
            "correlations, and forecasts."
        ),
        "direct_command_ttps": direct,
        "audit_only_classification_candidates": audit_only,
        "session_correlated_ttps": correlated,
        "prediction_only_hypotheses": prediction,
        "summary": {
            "direct_command_ttp_count": direct["count"],
            "audit_only_classification_count": audit_only["count"],
            "session_correlated_ttp_count": correlated["count"],
            "prediction_hypothesis_count": prediction["count"],
            "has_direct_command_evidence": direct["count"] > 0,
            "has_session_correlation_evidence": correlated["count"] > 0,
            "has_prediction_hypotheses": prediction["count"] > 0,
        },
    }


def attach_threat_evidence_layers(
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
    prediction_snapshot: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if report.get("schema_version") == "session_assessment.v4":
        # Visualization is context only. It cannot become a sibling authority
        # field or mutate canonical findings, hypotheses, status, or IDs.
        context = report.setdefault("non_authoritative_context", {})
        if not isinstance(context, dict):
            raise SessionAssessmentV4Error(
                "non_authoritative_context must be an object"
            )
        context["threat_evidence_layers"] = build_threat_evidence_layers(
            session_payload,
            prediction_snapshot=prediction_snapshot,
            hunting_context=build_session_correlation_hunting_context(
                session_payload.get("session_ttp_correlations", []),
                session_payload.get("session_id", "unknown"),
            ),
        )
        return report
    raise SessionAssessmentV4Error(
        "threat evidence layers can only attach to session_assessment.v4"
    )


def session_state_from_payload(payload: Dict[str, Any]) -> SessionState:
    state = SessionState(
        session_id=payload["session_id"],
        src_ip=payload.get("src_ip", "unknown"),
        start_time=payload.get("start_time", utc_now()),
    )
    for key, value in payload.items():
        if hasattr(state, key):
            setattr(state, key, value)
    return state


def deterministic_baseline_report(
    session_payload: Dict[str, Any],
    error: str,
    prediction_snapshot: Optional[Dict[str, Any]] = None,
    config: Optional[ProductionConfig] = None,
) -> Dict[str, Any]:
    safe_error = _safe_error_text(error)
    selected = config or ProductionConfig()
    report = build_session_assessment_v4(
        [session_payload],
        raw_events=session_payload.get("raw_events") or [],
        behavior_policy_path=selected.threat_hypothesis_behavior_policy_path,
        classification_policy=selected.classification_policy,
        classification_policy_path=selected.classification_rules_path,
        model_artifact_provenance=selected.prediction_policy,
        prediction_context=prediction_snapshot or {},
        enrichment_context=session_payload.get("enrichment_status") or {},
        correlation_context=session_payload.get("session_ttp_correlations") or [],
        mitre_cache_path=selected.mitre_attack_path,
        response_guidance_policy_path=selected.response_guidance_policy_path,
        response_guidance_asset_profile_path=(
            selected.response_guidance_asset_profile_path
        ),
    )
    report["status"] = "observation_only_abstention"
    report["abstention"] = {
        "abstained": True,
        "reason": "analysis_pipeline_failed",
    }
    report["behavioral_findings"] = []
    report["hypothesis_sets"] = []
    report["assessment_id"] = canonical_assessment_id(report)
    report["session_id"] = str(
        (report.get("canonical_evidence") or {}).get("session_id")
        or session_payload.get("session_id")
        or "unknown"
    ).strip()
    context = report["non_authoritative_context"]
    context["analysis_processing"] = {
        "status": "failed",
        "fallback": "canonical_observation_only_abstention",
        "error": safe_error,
    }
    report = attach_threat_evidence_layers(
        report, session_payload, prediction_snapshot
    )
    validate_session_assessment_v4(report, raise_on_error=True)
    return _safe_report_mapping(report)


def load_analysis_context(
    config: ProductionConfig,
    *,
    storage: Any = None,
) -> Dict[str, Any]:
    config.apply_environment()
    storage = storage or open_storage(config.database_url)
    feeds = None
    mitre_attack = None
    if config.enable_feed_loading:
        feeds = load_threat_feeds(
            cisa_cache_path=config.cisa_cache_path or None,
            sigma_cache_path=config.sigma_cache_path or None,
            allow_network_refresh=False,
        )
        mitre_attack = load_mitre_attack_db(
            cache_path=config.mitre_attack_path or None,
            silent=True,
            allow_network_refresh=False,
        )
        feed_status = collect_feed_status(config)
        feed_status["status"] = "loaded"
        feed_status["loading_enabled"] = True
    else:
        feed_status = {
            "status": "disabled",
            "loading_enabled": False,
        }
    enrichment_db = load_combined_ip_enrichment(
        storage=storage,
        file_path=config.enrichment_db_path,
        allow_stale=config.enrichment_allow_stale,
        local_max_bytes=config.local_enrichment_max_bytes,
        local_max_records=config.local_enrichment_max_records,
    )
    return {
        "storage": storage,
        "feeds": feeds,
        "mitre_attack": mitre_attack,
        "enrichment_db": enrichment_db,
        "feed_status": feed_status,
        "behavior_policy": load_behavior_policy(
            config.threat_hypothesis_behavior_policy_path
        ),
    }


def reconstruct_canonical_session_events(
    storage: Any,
    session_payload: Dict[str, Any],
    *,
    max_events: int,
) -> Dict[str, Any]:
    """Rebuild canonical event-derived fields from the exact durable prefix."""

    expected = session_payload.get("canonical_event_manifest")
    if not isinstance(expected, dict):
        raise SessionAssessmentV4Error(
            "analysis job lacks a canonical durable event manifest"
        )
    required = {
        "schema_version",
        "session_id",
        "through_event_id",
        "event_count",
        "manifest_sha256",
    }
    if set(expected) != required:
        raise SessionAssessmentV4Error(
            "analysis job canonical event manifest contract is invalid"
        )
    actual = storage.load_session_event_snapshot(
        str(expected.get("session_id") or ""),
        str(expected.get("through_event_id") or ""),
        max_events,
    )
    actual_summary = {key: actual[key] for key in required}
    if actual_summary != expected:
        raise SessionAssessmentV4Error(
            "durable session evidence does not match the analysis manifest"
        )
    selected_session_id = str(expected.get("session_id") or "")
    events = list(actual["events"])
    if len(events) != int(expected.get("event_count") or -1):
        raise SessionAssessmentV4Error(
            "durable session evidence count does not match the analysis manifest"
        )
    for event in events:
        event_session_id = str(event.get("session") or "").strip()
        if event_session_id and event_session_id != selected_session_id:
            raise SessionAssessmentV4Error(
                "durable session evidence contains a conflicting session identity"
            )

    commands: List[str] = []
    commands_success: List[str] = []
    commands_failed: List[str] = []
    for event in events:
        eventid = str(event.get("eventid") or "").strip()
        if eventid not in {
            "cowrie.command.input",
            "cowrie.command.success",
            "cowrie.command.failed",
        }:
            continue
        command = str(event.get("input") or "").strip()
        if not command:
            continue
        commands.append(command)
        reported_success = (
            event.get("success") == 1 or eventid == "cowrie.command.success"
        )
        reported_failure = (
            event.get("success") == 0 or eventid == "cowrie.command.failed"
        )
        if reported_success:
            commands_success.append(command)
        elif reported_failure:
            commands_failed.append(command)

    reconstructed = dict(session_payload)
    reconstructed["session_id"] = selected_session_id
    reconstructed["raw_events"] = events
    reconstructed["commands"] = commands
    reconstructed["commands_success"] = commands_success
    reconstructed["commands_failed"] = commands_failed
    reconstructed["login_success"] = any(
        str(event.get("eventid") or "") == "cowrie.login.success"
        for event in events
    )
    reconstructed["login_attempts"] = sum(
        1
        for event in events
        if str(event.get("eventid") or "") == "cowrie.login.failed"
    )
    # Cached graphs may have been built from the bounded monitor projection.
    # The v4 builder deterministically reconstructs them from this exact event
    # set and the pinned behavior policy.
    reconstructed["session_evidence_graph"] = {}
    reconstructed["session_evidence_graph_summary"] = {}
    reconstructed["canonical_event_manifest"] = dict(expected)
    return reconstructed


async def analyze_job(
    job: Dict[str, Any],
    config: ProductionConfig,
    coordinator_class: Type[Any] = CanonicalAssessmentCoordinator,
    prediction_snapshot: Optional[Dict[str, Any]] = None,
    storage: Any = None,
) -> Dict[str, Any]:
    session_payload = job.get("session") or json.loads(job["payload_json"])
    selected_storage = storage or open_storage(config.database_url)
    session_payload = reconstruct_canonical_session_events(
        selected_storage,
        session_payload,
        max_events=config.canonical_evidence_max_events,
    )
    state = session_state_from_payload(session_payload)
    if not getattr(state, "bpg_list", None) or not getattr(state, "ioc_summary", None):
        attach_runtime_context(state)
    context = load_analysis_context(config, storage=selected_storage)
    trigger = build_pipeline_trigger(
        coordinator_class=coordinator_class,
        feeds=context["feeds"],
        mitre_db=context["mitre_attack"],
        enrichment_db=context["enrichment_db"],
        feed_loading_enabled=config.enable_feed_loading,
        feed_status=context["feed_status"],
        behavior_policy_document=context["behavior_policy"],
        behavior_policy_path=config.threat_hypothesis_behavior_policy_path,
        classification_policy=config.classification_policy,
        classification_rules_path=config.classification_rules_path,
        prediction_policy=config.prediction_policy,
        prediction_policy_path=config.prediction_policy_path,
        prediction_context=prediction_snapshot,
        response_guidance_policy_path=config.response_guidance_policy_path,
        response_guidance_asset_profile_path=config.response_guidance_asset_profile_path,
        mitre_cache_path=config.mitre_attack_path,
    )
    if config.analysis_suppress_stdout:
        with contextlib.redirect_stdout(io.StringIO()):
            result = trigger(state)
    else:
        result = trigger(state)
    if not result:
        safe_pipeline_error = _safe_error_text(
            getattr(
                state,
                "pipeline_error",
                "analysis pipeline returned no report",
            )
        )
        raise RuntimeError(safe_pipeline_error) from None
    if result.get("schema_version") != "session_assessment.v4":
        raise SessionAssessmentV4Error(
            "new analysis reports must use session_assessment.v4"
        )
    result.setdefault("session_id", state.session_id)
    result.setdefault("created_at", utc_now())
    result.setdefault("worker", "analysis_worker")
    result.setdefault(
        "correlation_id",
        safe_correlation_id(
            session_payload.get("correlation_id"),
            str(job.get("job_id") or ""),
        ),
    )
    hunting_context = build_session_correlation_hunting_context(
        session_payload.get("session_ttp_correlations", []),
        session_payload.get("session_id", state.session_id),
    )
    context_payload = result.setdefault("non_authoritative_context", {})
    if not isinstance(context_payload, dict):
        raise SessionAssessmentV4Error(
            "non_authoritative_context must be an object"
        )
    context_payload["threat_hunting"] = hunting_context
    result = attach_threat_evidence_layers(result, session_payload, prediction_snapshot)
    if config.enable_actor_attribution:
        attribution = enrich_report_with_actor_attribution(
            {},
            session_payload,
            config.actor_db_path,
            mitre_db=context["mitre_attack"],
        )
        context_payload["actor_attribution"] = {
            "authority": "non_authoritative_context_only",
            "actor_matches": attribution.get("actor_matches") or [],
        }
    validate_session_assessment_v4(result, raise_on_error=True)
    result = attach_report_artifacts(result, session_payload, config)
    validate_session_assessment_v4(result, raise_on_error=True)
    return result


class AnalysisWorker:
    def __init__(self, config: ProductionConfig) -> None:
        self.config = config
        self.storage = open_storage(config.database_url)
        self.worker_owner = new_job_owner("analysis")

    def _fail_claim(self, job: Dict[str, Any], exc: Exception, *, retryable: bool) -> str:
        error_code, error_type, classified_retryable = job_failure_identity(
            "analysis", exc
        )
        return self.storage.fail_analysis_job(
            job["job_id"],
            job["claim_owner"],
            job["claim_token"],
            error_code,
            error_type,
            retryable and classified_retryable,
            self.config.analysis_max_attempts,
            job_retry_delay(self.config, int(job.get("attempts") or 1)),
        )

    async def process_once(
        self,
        coordinator_class: Type[Any] = CanonicalAssessmentCoordinator,
        *,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> int:
        save_feed_status(self.storage, self.config)
        processed = 0
        for _ in range(self.config.analysis_batch_size):
            if should_stop is not None and should_stop():
                break
            jobs = self.storage.claim_analysis_jobs(
                self.worker_owner,
                1,
                self.config.job_lease_seconds,
                self.config.analysis_max_attempts,
            )
            if not jobs:
                break
            job = jobs[0]
            if should_stop is not None and should_stop():
                self.storage.release_job_claim(
                    "analysis",
                    job["job_id"],
                    job["claim_owner"],
                    job["claim_token"],
                )
                break
            started_at = time.monotonic()
            session_payload = job.get("session") or {}
            session_id = job.get("session_id") or session_payload.get("session_id", "unknown")
            correlation_id = safe_correlation_id(
                session_payload.get("correlation_id"),
                str(job["job_id"]),
            )
            latest_prediction_row = self.storage.get_current_prediction_snapshot(
                session_id
            )
            latest_prediction = (
                latest_prediction_row.get("payload")
                if isinstance(latest_prediction_row, dict)
                else None
            )
            with JobLeaseHeartbeat(self.storage, self.config, "analysis", job) as heartbeat:
                try:
                    # Analysis jobs contain a bounded monitor projection. It is
                    # never an authority input. Reconstruct and bind the exact
                    # durable prefix before any skip decision or report path.
                    canonical_session = reconstruct_canonical_session_events(
                        self.storage,
                        job["session"],
                        max_events=self.config.canonical_evidence_max_events,
                    )
                except Exception as exc:
                    retry = int(job["attempts"]) < self.config.analysis_max_attempts
                    status = self._fail_claim(job, exc, retryable=retry)
                    print(
                        _safe_log_json(
                            {
                                "service": "analysis_worker",
                                "job_id": job["job_id"],
                                "correlation_id": correlation_id,
                                "status": status,
                                "error": _safe_exception_text(exc),
                                "canonical_evidence_status": "unavailable",
                                "partial_report_created": False,
                                "timestamp": utc_now(),
                            },
                        ),
                        flush=True,
                    )
                    continue

                canonical_job = dict(job)
                canonical_job["session"] = canonical_session
                skip_reason = ""
                if self.config.analysis_skip_empty_sessions:
                    skip_reason = session_analysis_skip_reason(canonical_session)
                if skip_reason:
                    skipped = self.storage.skip_analysis_job(
                        job["job_id"],
                        job["claim_owner"],
                        job["claim_token"],
                        skip_reason,
                    )
                    processed += int(skipped)
                    print(
                        _safe_log_json(
                            {
                                "service": "analysis_worker",
                                "job_id": job["job_id"],
                                "session_id": job.get("session_id", "unknown"),
                                "correlation_id": correlation_id,
                                "status": "skipped",
                                "reason": skip_reason,
                                "canonical_evidence_status": "verified",
                                "timestamp": utc_now(),
                            },
                        ),
                        flush=True,
                    )
                    continue

                try:
                    report = await analyze_job(
                        canonical_job,
                        self.config,
                        coordinator_class=coordinator_class,
                        prediction_snapshot=latest_prediction,
                        storage=self.storage,
                    )
                except Exception as exc:
                    safe_error = _safe_exception_text(exc)
                    retry = int(job["attempts"]) < self.config.analysis_max_attempts
                    status = "retry" if retry else "failed"
                    if retry or not self.config.analysis_fallback_on_failure:
                        transition = self._fail_claim(job, exc, retryable=retry)
                        status = transition
                    else:
                        try:
                            # Re-read and re-verify the immutable durable prefix
                            # for fallback. Never reuse the bounded queued
                            # projection or create artifacts after a mismatch.
                            fallback_session = reconstruct_canonical_session_events(
                                self.storage,
                                job["session"],
                                max_events=(
                                    self.config.canonical_evidence_max_events
                                ),
                            )
                            fallback = deterministic_baseline_report(
                                fallback_session,
                                safe_error,
                                prediction_snapshot=latest_prediction,
                                config=self.config,
                            )
                            fallback.setdefault("correlation_id", correlation_id)
                            validate_session_assessment_v4(
                                fallback, raise_on_error=True
                            )
                            fallback = attach_report_artifacts(
                                fallback,
                                fallback_session,
                                self.config,
                            )
                            validate_session_assessment_v4(
                                fallback, raise_on_error=True
                            )
                            heartbeat.check(renew=True)
                            report_id = self.storage.complete_analysis_job(
                                job["job_id"],
                                job["claim_owner"],
                                job["claim_token"],
                                fallback,
                            )
                            if report_id is None:
                                status = "stale_claim"
                            else:
                                processed += 1
                                status = "fallback_reported"
                        except Exception as fallback_exc:
                            safe_error = _safe_exception_text(fallback_exc)
                            status = self._fail_claim(
                                job,
                                fallback_exc,
                                retryable=False,
                            )
                    print(
                        _safe_log_json(
                            {
                                "service": "analysis_worker",
                                "job_id": job["job_id"],
                                "correlation_id": correlation_id,
                                "status": status,
                                "error": safe_error,
                                "report_generation_latency_ms": round(
                                    max(time.monotonic() - started_at, 0.0) * 1000,
                                    3,
                                ),
                                "timestamp": utc_now(),
                            },
                        ),
                        flush=True,
                    )
                    continue
                try:
                    report.setdefault("correlation_id", correlation_id)
                    heartbeat.check(renew=True)
                    report_id = self.storage.complete_analysis_job(
                        job["job_id"],
                        job["claim_owner"],
                        job["claim_token"],
                        report,
                    )
                except Exception as exc:
                    self._fail_claim(job, exc, retryable=True)
                    print(
                        _safe_log_json(
                            {
                                "service": "analysis_worker",
                                "job_id": job["job_id"],
                                "correlation_id": correlation_id,
                                "status": "completion_failed",
                                "error": _safe_exception_text(exc),
                                "report_generation_latency_ms": round(
                                    max(time.monotonic() - started_at, 0.0) * 1000,
                                    3,
                                ),
                                "timestamp": utc_now(),
                            }
                        ),
                        flush=True,
                    )
                    continue
                if report_id is None:
                    continue
                processed += 1
                print(
                    _safe_log_json(
                        {
                            "service": "analysis_worker",
                            "job_id": job["job_id"],
                            "session_id": job.get("session_id", "unknown"),
                            "correlation_id": correlation_id,
                            "status": "succeeded",
                            "report_generation_latency_ms": round(
                                max(time.monotonic() - started_at, 0.0) * 1000,
                                3,
                            ),
                            "timestamp": utc_now(),
                        },
                    ),
                    flush=True,
                )
        return processed

    def run_forever(self, lifecycle: Optional[ServiceLifecycle] = None) -> None:
        control = lifecycle or ServiceLifecycle()
        with control.signal_handlers():
            while not control.stopping:
                processed = asyncio.run(
                    self.process_once(should_stop=lambda: control.stopping)
                )
                if processed:
                    print(
                        _safe_log_json(
                            {
                                "service": "analysis_worker",
                                "processed": processed,
                                "timestamp": utc_now(),
                            },
                        ),
                        flush=True,
                    )
                control.wait(self.config.worker_poll_seconds)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the closed-session analysis worker.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--once", action="store_true", help="Process one batch and exit.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    worker = AnalysisWorker(config)
    if args.once:
        processed = asyncio.run(worker.process_once())
        print(_safe_log_json({"service": "analysis_worker", "processed": processed}))
        return 0
    worker.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
