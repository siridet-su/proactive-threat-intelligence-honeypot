"""Session monitor worker for queued Cowrie events."""

from __future__ import annotations

import argparse
import json
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional

from production.enrichment.mitre_attack_loader import load_mitre_attack_db
from production.workers.session_monitor import SessionMonitor
from production.enrichment.threat_feed_loader import load_threat_feeds

from production.classification.classification_pipeline import NotebookParityClassifier
from production.utils.config import ProductionConfig
from production.utils.credential_hmac import (
    load_credential_hmac_keyring,
    resolve_credential_hmac_keyring_path,
    validate_production_credential_policy,
)
from production.enrichment.enrichment_cache import (
    enqueue_event_observables,
    enqueue_session_observables,
    load_combined_ip_enrichment,
)
from production.enrichment.feed_status import save_feed_status
from production.correlation.observable_sightings import (
    extract_event_observable_sightings,
    extract_session_observable_sightings,
    record_sightings,
)
from production.reporting.analysis_policy import (
    mark_session_analysis_queued,
    mark_session_analysis_skipped,
    mark_session_outcome,
    session_analysis_skip_reason,
)
from production.correlation.campaign_clustering import create_or_update_campaign
from production.prediction.realtime_prediction import (
    RealtimePredictionEngine,
    build_actor_fingerprint_transition_model,
    build_transition_model,
)
from production.prediction.predictive_alerts import evaluate_predictive_alert
from production.utils.runtime_context import attach_runtime_context
from production.utils.serialization import session_to_payload, stable_id, utc_now
from production.prediction.session_features import build_session_features
from production.correlation.session_ttp_correlation import apply_session_ttp_correlations, load_knowledge as load_session_ttp_correlation_knowledge
from production.reporting.smb_decision import RISK_ORDER, build_smb_decision_from_paths
from production.classification.securebert_classifier import load_securebert_classifier
from production.storage import open_storage, safe_database_label
from production.storage.session_provenance import (
    SESSION_SOURCE_PRODUCTION_LIVE,
    normalize_session_source,
)
from production.utils.feedback import build_auto_evidence_feedback
from production.utils.sensitive_data import redact_for_artifact, redact_for_log
from production.workers.threat_hunt_worker import enqueue_threat_hunts_for_session


DEFAULT_PREDICTION_TRIGGER_EVENTIDS = [
    "cowrie.login.success",
    "cowrie.login.failed",
    "cowrie.session.file_download",
    "cowrie.session.file_upload",
    "cowrie.session.closed",
]

DEFAULT_PREDICTION_TRIGGER_PREFIXES = [
    "cowrie.command.",
]


def _safe_exception_text(exc: BaseException) -> str:
    """Return a bounded exception description using the central redactor."""

    return f"{type(exc).__name__}: {redact_for_log(exc, max_string_chars=1_000)}"


def alert_payload(alert: Any) -> Dict[str, Any]:
    payload = dict(getattr(alert, "__dict__", alert))
    payload.setdefault("alert_id", stable_id("alert", payload))
    payload.setdefault("created_at", utc_now())
    return payload


class SessionWorker:
    def __init__(self, config: ProductionConfig) -> None:
        self.config = config
        self.config.credential_policy = validate_production_credential_policy(
            config.credential_policy
        )
        keyring_path = resolve_credential_hmac_keyring_path(
            config.credential_hmac_keyring_file
        )
        self.credential_hasher = load_credential_hmac_keyring(keyring_path)
        config.apply_environment()
        self.storage = open_storage(config.database_url)
        self.feeds = None
        self.mitre_db = None
        self.enrichment_db: Dict[str, Any] = {}
        self._base_prediction_policy = deepcopy(config.prediction_policy or {})
        self._calibration_output_mtime: Optional[float] = None
        self.weight_calibration_status: Dict[str, Any] = {
            "enabled": bool((config.calibration_policy or {}).get("enabled", True)),
            "status": "not_checked",
        }
        self._session_latest_snapshots: Dict[str, Dict[str, Any]] = {}
        self._session_prediction_snapshots: Dict[str, List[Dict[str, Any]]] = {}
        self.bert_fn = load_securebert_classifier(config)
        self.classifier = None
        self.session_ttp_correlation_policy = self._load_session_ttp_correlation_policy()
        self._reload_calibration_output_if_changed(force=True)
        self.prediction_engine = self._new_prediction_engine()
        if config.enable_feed_loading:
            self.feeds = load_threat_feeds(
                cisa_cache_path=config.cisa_cache_path or None,
                sigma_cache_path=config.sigma_cache_path or None,
            )
            self.mitre_db = load_mitre_attack_db(
                cache_path=config.mitre_attack_path or None,
                silent=True,
            )
        self._refresh_enrichment_cache()
        self.classifier = NotebookParityClassifier(
            bert_fn=self.bert_fn,
            mitre_db=self.mitre_db,
            high_confidence=float(config.classification_policy.get("bert_min_confidence", 0.55)),
            rule_policy_path=config.classification_rules_path,
        )
        save_feed_status(self.storage, config)
        self.monitor = self._new_monitor()

    def _session_source(self) -> str:
        return normalize_session_source(
            getattr(self.config, "session_source", ""),
            SESSION_SOURCE_PRODUCTION_LIVE,
        )

    def _session_payload(self, state: Any) -> Dict[str, Any]:
        payload = session_to_payload(state)
        payload["session_source"] = self._session_source()
        return payload

    def _load_session_ttp_correlation_policy(self) -> Dict[str, Any]:
        if not self.config.enable_session_ttp_correlation:
            return {"policy": {"enabled": False, "rules": []}}
        path = self.config.session_ttp_correlation_policy_path
        pack_paths = self.config.session_ttp_knowledge_pack_paths
        try:
            return load_session_ttp_correlation_knowledge(path, pack_paths)
        except Exception as exc:
            print(
                json.dumps(
                    {
                        "service": "session_worker",
                        "warning": "session_ttp_correlation_policy_load_failed",
                        "path": path,
                        "knowledge_pack_paths": pack_paths,
                        "error": _safe_exception_text(exc),
                        "timestamp": utc_now(),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            return {"policy": {"enabled": False, "rules": []}}

    def _load_transition_model(self) -> Dict[str, Any]:
        policy = self.config.prediction_policy or {}
        limit = int(policy.get("transition_history_limit", 500))
        try:
            if hasattr(self.storage, "list_session_rows"):
                rows = self.storage.list_session_rows(
                    limit=limit,
                    session_source=SESSION_SOURCE_PRODUCTION_LIVE,
                    external_only=True,
                )
            else:
                rows = self.storage.list_rows("sessions", limit=limit)
        except Exception:
            return build_transition_model([])

        payloads: List[Dict[str, Any]] = []
        for row in rows:
            raw = row.get("payload_json")
            if isinstance(raw, dict):
                payloads.append(raw)
            elif isinstance(raw, str):
                try:
                    loaded = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(loaded, dict):
                    payloads.append(loaded)
        return build_transition_model(
            payloads,
            prefix_max_length=int(policy.get("prefix_max_length", 3)),
            source_name="local_transition",
            source_database=safe_database_label(self.config.database_url),
            recency_half_life_sessions=float(policy.get("recency_decay_half_life_sessions") or 0.0),
        )

    def _load_external_transition_model(self) -> Dict[str, Any]:
        policy = self.config.prediction_policy or {}
        path_text = str(policy.get("external_transition_model_path") or "").strip()
        if not path_text:
            return build_transition_model([])
        path = Path(path_text)
        if not path.exists():
            print(
                json.dumps(
                    {
                        "service": "session_worker",
                        "warning": "external_transition_model_not_found",
                        "path": path_text,
                        "timestamp": utc_now(),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            return build_transition_model([])
        try:
            with path.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            print(
                json.dumps(
                    {
                        "service": "session_worker",
                        "warning": "external_transition_model_load_failed",
                        "path": path_text,
                        "error": _safe_exception_text(exc),
                        "timestamp": utc_now(),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            return build_transition_model([])
        if isinstance(loaded, dict) and isinstance(loaded.get("model"), dict):
            return loaded["model"]
        if isinstance(loaded, dict):
            return loaded
        return build_transition_model([])

    def _load_actor_fingerprint_transition_model(self) -> Dict[str, Any]:
        policy = self.config.prediction_policy or {}
        actor_policy = policy.get("actor_fingerprint_prior") or {}
        if not isinstance(actor_policy, dict):
            actor_policy = {}
        if not bool(actor_policy.get("enabled", False)):
            return build_actor_fingerprint_transition_model([], policy)

        path_text = str(actor_policy.get("model_path") or policy.get("actor_fingerprint_model_path") or "").strip()
        if path_text:
            path = Path(path_text)
            if not path.exists():
                print(
                    json.dumps(
                        {
                            "service": "session_worker",
                            "warning": "actor_fingerprint_transition_model_not_found",
                            "path": path_text,
                            "timestamp": utc_now(),
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
            else:
                try:
                    with path.open("r", encoding="utf-8") as f:
                        loaded = json.load(f)
                except (OSError, json.JSONDecodeError) as exc:
                    print(
                        json.dumps(
                            {
                                "service": "session_worker",
                                "warning": "actor_fingerprint_transition_model_load_failed",
                                "path": path_text,
                                "error": _safe_exception_text(exc),
                                "timestamp": utc_now(),
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                else:
                    if isinstance(loaded, dict) and isinstance(loaded.get("model"), dict):
                        return loaded["model"]
                    if isinstance(loaded, dict):
                        return loaded

        limit = int(actor_policy.get("history_limit") or policy.get("transition_history_limit", 500))
        try:
            if hasattr(self.storage, "list_session_rows"):
                rows = self.storage.list_session_rows(
                    limit=max(limit, 1),
                    session_source=SESSION_SOURCE_PRODUCTION_LIVE,
                    external_only=True,
                )
            else:
                rows = self.storage.list_rows("sessions", limit=max(limit, 1))
        except Exception:
            return build_actor_fingerprint_transition_model([], policy)

        payloads: List[Dict[str, Any]] = []
        for row in rows:
            raw = row.get("payload_json")
            if isinstance(raw, dict):
                payloads.append(raw)
            elif isinstance(raw, str):
                try:
                    loaded = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(loaded, dict):
                    payloads.append(loaded)
        return build_actor_fingerprint_transition_model(
            payloads,
            policy=policy,
            prefix_max_length=int(actor_policy.get("prefix_max_length") or policy.get("prefix_max_length", 3)),
            source_database=safe_database_label(self.config.database_url),
            recency_half_life_sessions=float(policy.get("recency_decay_half_life_sessions") or 0.0),
        )

    def _new_prediction_engine(self) -> RealtimePredictionEngine:
        return RealtimePredictionEngine(
            self.config.prediction_policy,
            transition_model=self._load_transition_model(),
            external_transition_model=self._load_external_transition_model(),
            actor_fingerprint_transition_model=self._load_actor_fingerprint_transition_model(),
        )

    def _merge_prediction_policy_overlay(self, overlay: Dict[str, Any]) -> Dict[str, Any]:
        merged = deepcopy(self._base_prediction_policy)
        for key, value in overlay.items():
            if key == "weights" and isinstance(value, dict):
                base_weights = dict(merged.get("weights") or {})
                base_weights.update(value)
                merged["weights"] = base_weights
            elif isinstance(value, dict) and isinstance(merged.get(key), dict):
                nested = dict(merged.get(key) or {})
                nested.update(value)
                merged[key] = nested
            else:
                merged[key] = value
        return merged

    def _reload_calibration_output_if_changed(self, force: bool = False) -> None:
        policy = self.config.calibration_policy or {}
        enabled = bool(policy.get("enabled", True))
        output_path = str(policy.get("output_path") or "").strip()
        if not enabled:
            self.config.prediction_policy = deepcopy(self._base_prediction_policy)
            self.weight_calibration_status = {
                "enabled": False,
                "status": "disabled",
                "reason": "calibration policy disabled",
            }
            return
        if not output_path:
            self.config.prediction_policy = deepcopy(self._base_prediction_policy)
            self.weight_calibration_status = {
                "enabled": True,
                "status": "missing",
                "reason": "calibration output path is not configured",
            }
            return

        path = Path(output_path)
        if not path.exists():
            if force or self._calibration_output_mtime != -1.0:
                self.config.prediction_policy = deepcopy(self._base_prediction_policy)
                self.weight_calibration_status = {
                    "enabled": True,
                    "status": "missing",
                    "path": output_path,
                    "reason": "calibration output file does not exist",
                }
                self._calibration_output_mtime = -1.0
            return

        mtime = path.stat().st_mtime
        if not force and self._calibration_output_mtime == mtime:
            return
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.config.prediction_policy = deepcopy(self._base_prediction_policy)
            self.weight_calibration_status = {
                "enabled": True,
                "status": "error",
                "path": output_path,
                "reason": _safe_exception_text(exc),
            }
            self._calibration_output_mtime = mtime
            return
        if not isinstance(loaded, dict):
            self.config.prediction_policy = deepcopy(self._base_prediction_policy)
            self.weight_calibration_status = {
                "enabled": True,
                "status": "error",
                "path": output_path,
                "reason": "calibration output is not a JSON object",
            }
            self._calibration_output_mtime = mtime
            return

        apply_output = bool(policy.get("apply_output", True))
        applied = bool(loaded.get("applied") or loaded.get("apply"))
        overlay = loaded.get("policy_overlay") or {}
        if apply_output and applied and isinstance(overlay, dict):
            self.config.prediction_policy = self._merge_prediction_policy_overlay(overlay)
            status = "applied"
        else:
            self.config.prediction_policy = deepcopy(self._base_prediction_policy)
            status = str(loaded.get("status") or "not_applied")
        self.weight_calibration_status = redact_for_artifact(
            {
                "enabled": True,
                "status": status,
                "path": output_path,
                "run_id": loaded.get("run_id") or "",
                "generated_at": loaded.get("generated_at") or "",
                "reason": loaded.get("reason") or "",
                "applied": apply_output and applied,
                "inputs": loaded.get("inputs") or {},
            }
        )
        self._calibration_output_mtime = mtime

    def _refresh_prediction_engine(self) -> None:
        self._reload_calibration_output_if_changed()
        if self.prediction_engine.enabled:
            self.prediction_engine = self._new_prediction_engine()

    def _new_monitor(self) -> SessionMonitor:
        return SessionMonitor(
            feeds=self.feeds,
            mitre_db=self.mitre_db,
            enrichment_db=self.enrichment_db,
            bert_fn=self.bert_fn,
            classification_fn=self.classifier.classify if self.classifier else None,
            prediction_fn=self._predict_next_for_alert,
            on_alert=self._on_alert,
            on_session_end=self._on_session_end,
            classification_policy=self.config.classification_policy,
            credential_policy=self.config.credential_policy,
            credential_hasher=self.credential_hasher,
        )

    def _refresh_enrichment_cache(self) -> None:
        self.enrichment_db = load_combined_ip_enrichment(
            storage=self.storage,
            file_path=self.config.enrichment_db_path,
            allow_stale=self.config.enrichment_allow_stale,
        )
        if hasattr(self, "monitor"):
            self.monitor.enrichment_db = self.enrichment_db

    def _apply_session_ttp_correlations(self, state: Any) -> None:
        if not self.config.enable_session_ttp_correlation:
            setattr(state, "session_ttp_correlations", [])
            setattr(
                state,
                "session_ttp_correlation_summary",
                {"status": "disabled", "correlation_count": 0},
            )
            return
        payload = self._session_payload(state)
        updated = apply_session_ttp_correlations(payload, self.session_ttp_correlation_policy)
        setattr(state, "session_evidence_graph", updated.get("session_evidence_graph") or {})
        setattr(
            state,
            "session_evidence_graph_summary",
            updated.get("session_evidence_graph_summary") or {},
        )
        setattr(state, "session_ttp_correlations", updated.get("session_ttp_correlations") or [])
        setattr(
            state,
            "session_ttp_correlation_summary",
            updated.get("session_ttp_correlation_summary") or {},
        )

    def _on_alert(self, alert: Any) -> None:
        self.storage.store_alert(alert_payload(alert))

    def _prediction_trigger_for_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Return whether a Cowrie event should create a prediction snapshot.

        All events are still stored, sighted, and applied to SessionMonitor.
        This gate only controls durable prediction snapshot creation so metadata
        events do not make the realtime prediction history noisy.
        """
        eventid = str(event.get("eventid") or "").strip()
        policy = self.config.prediction_policy or {}
        trigger_policy = policy.get("prediction_triggers") or {}
        if not isinstance(trigger_policy, dict):
            trigger_policy = {}

        if trigger_policy.get("enabled") is False:
            return {
                "matched": True,
                "eventid": eventid,
                "reason": "prediction trigger filtering disabled by policy",
                "filter_enabled": False,
            }

        exact_eventids = trigger_policy.get("eventids")
        if exact_eventids is None:
            exact_eventids = DEFAULT_PREDICTION_TRIGGER_EVENTIDS
        exact = {str(item).strip() for item in exact_eventids or [] if str(item).strip()}

        prefixes = trigger_policy.get("eventid_prefixes")
        if prefixes is None:
            prefixes = DEFAULT_PREDICTION_TRIGGER_PREFIXES
        prefix_values = [str(item).strip() for item in prefixes or [] if str(item).strip()]

        if eventid in exact:
            return {
                "matched": True,
                "eventid": eventid,
                "reason": f"eventid matched prediction trigger policy: {eventid}",
                "filter_enabled": True,
                "match_type": "eventid",
            }
        for prefix in prefix_values:
            if eventid.startswith(prefix):
                return {
                    "matched": True,
                    "eventid": eventid,
                    "reason": f"eventid matched prediction trigger prefix: {prefix}",
                    "filter_enabled": True,
                    "match_type": "eventid_prefix",
                    "matched_prefix": prefix,
                }
        return {
            "matched": False,
            "eventid": eventid,
            "reason": "event does not materially change attack evidence for realtime prediction",
            "filter_enabled": True,
        }

    def _maybe_store_smb_decision_alert(self, decision: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        if not self.config.enable_smb_decision_alerts:
            return
        risk = decision.get("risk") or {}
        severity = str(risk.get("severity") or "info").lower()
        threshold = str(self.config.smb_alert_min_severity or "high").lower()
        if RISK_ORDER.get(severity, 0) < RISK_ORDER.get(threshold, 3):
            return
        actions = [
            str(item.get("action_id") or "")
            for item in (decision.get("immediate_actions") or [])[:3]
            if isinstance(item, dict)
        ]
        alert_id = stable_id(
            "smbalert",
            {
                "session_id": decision.get("session_id"),
                "severity": severity,
                "risk_rule": risk.get("rule_id") or "",
                "actions": actions,
            },
        )
        self.storage.store_alert(
            {
                "alert_id": alert_id,
                "session_id": decision.get("session_id", "unknown"),
                "severity": severity.upper(),
                "reason": risk.get("reason") or f"SMB decision risk: {severity}",
                "created_at": utc_now(),
                "alert_type": "smb_decision",
                "payload": {
                    "alert_type": "smb_decision",
                    "decision_id": decision.get("decision_id"),
                    "snapshot_id": snapshot.get("snapshot_id"),
                    "risk": risk,
                    "likely_goal": decision.get("likely_goal") or {},
                    "likely_next_step": decision.get("likely_next_step") or {},
                    "immediate_actions": decision.get("immediate_actions") or [],
                    "asset_context": decision.get("asset_context") or {},
                    "trust": decision.get("trust") or {},
                },
            }
        )

    def _maybe_store_predictive_alert(self, snapshot: Dict[str, Any]) -> None:
        alert, evaluation = evaluate_predictive_alert(snapshot, self.config.prediction_policy or {})
        snapshot["predictive_alert"] = evaluation
        if not alert:
            return
        self.storage.store_alert(alert)
        escalation = {
            "status": "not_attempted",
            "observable_type": "ip",
            "observable_value": snapshot.get("src_ip") or "",
            "priority": "urgent",
            "reason": "predictive alert created",
        }
        src_ip = str(snapshot.get("src_ip") or "").strip()
        if src_ip and src_ip.lower() != "unknown" and self.config.enable_enrichment_jobs:
            reason = (
                f"predictive_alert:{alert.get('alert_id')} "
                f"tactic={alert.get('predicted_tactic')} severity={alert.get('severity')}"
            )
            job_id, queued = self.storage.enqueue_enrichment_job(
                "ip",
                src_ip,
                session_id=str(snapshot.get("session_id") or ""),
                payload={
                    "source": "predictive_alert",
                    "snapshot_id": snapshot.get("snapshot_id") or "",
                    "alert_id": alert.get("alert_id") or "",
                    "predicted_tactic": alert.get("predicted_tactic") or "",
                    "predicted_confidence": alert.get("predicted_confidence") or "",
                    "predicted_score": alert.get("predicted_score"),
                },
                priority="urgent",
                priority_reason=reason,
            )
            updated = self.storage.reprioritize_enrichment_jobs(
                src_ip,
                observable_type="ip",
                priority="urgent",
                reason=reason,
                session_id=str(snapshot.get("session_id") or ""),
            )
            escalation.update(
                {
                    "status": "queued_or_reprioritized" if queued or updated else "fresh_cache_or_no_queued_job",
                    "job_id": job_id,
                    "queued": queued,
                    "reprioritized_jobs": updated,
                    "reason": reason,
                }
            )
        elif not self.config.enable_enrichment_jobs:
            escalation["status"] = "disabled"
            escalation["reason"] = "enrichment jobs disabled"
        else:
            escalation["status"] = "skipped"
            escalation["reason"] = "snapshot has no usable source IP"
        snapshot["predictive_alert"]["enrichment_escalation"] = escalation

    def _apply_campaign_clustering(self, payload: Dict[str, Any], status: str) -> Dict[str, Any]:
        try:
            summary = create_or_update_campaign(
                self.storage,
                payload,
                self.config.campaign_policy,
                status=status,
            )
        except Exception as exc:
            summary = {
                "status": "error",
                "reason": _safe_exception_text(exc),
                "session_id": payload.get("session_id") or "unknown",
            }
            print(
                json.dumps(
                    {
                        "service": "session_worker",
                        "warning": "campaign_clustering_failed",
                        "session_id": payload.get("session_id") or "unknown",
                        "error": summary["reason"],
                        "timestamp": utc_now(),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
        payload["campaign_summary"] = summary
        if summary.get("campaign_id"):
            payload["campaign_id"] = summary.get("campaign_id")
        return summary

    def _predict_next_for_alert(self, state: Any) -> List[str]:
        """Return alert text predictions from the production scorer engine.

        This keeps legacy realtime alerts aligned with the monitor/API output.
        It deliberately does not store a snapshot; the normal event path stores
        the durable prediction immediately after SessionMonitor.on_event().
        """
        if not self.prediction_engine.enabled:
            return []
        if hasattr(self.monitor, "_apply_session_enrichment"):
            self.monitor._apply_session_enrichment(state)
        self._apply_session_ttp_correlations(state)
        payload = self._session_payload(state)
        payload.setdefault("status", "closed" if payload.get("is_ended") else "active")
        mark_session_outcome(payload)
        features = build_session_features(payload)
        snapshot = self.prediction_engine.predict(features, event_id="alert-preview")
        return [
            str(tactic or "").strip()
            for tactic in snapshot.get("prediction") or []
            if str(tactic or "").strip()
        ]

    def _save_prediction_snapshot(
        self,
        state: Any,
        event: Dict[str, Any],
        event_id: str = "",
        trigger_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self.prediction_engine.enabled:
            return
        if hasattr(self.monitor, "_apply_session_enrichment"):
            self.monitor._apply_session_enrichment(state)
        self._apply_session_ttp_correlations(state)
        payload = self._session_payload(state)
        payload.setdefault("status", "closed" if payload.get("is_ended") else "active")
        mark_session_outcome(payload)
        self._apply_campaign_clustering(payload, "closed" if payload.get("is_ended") else "active")
        features = build_session_features(payload, current_event=event)
        snapshot = self.prediction_engine.predict(features, event_id=event_id)
        snapshot["weight_calibration"] = self.weight_calibration_status
        snapshot["prediction_trigger"] = trigger_info or self._prediction_trigger_for_event(event)
        if self.config.enable_smb_decisions:
            decision = build_smb_decision_from_paths(
                session_payload=payload,
                prediction_snapshot=snapshot,
                asset_profile_path=self.config.smb_asset_profile_path,
                action_policy_path=self.config.smb_action_policy_path,
                mitre_attack_path=self.config.mitre_attack_path,
            )
            snapshot["smb_decision"] = decision
            self._maybe_store_smb_decision_alert(decision, snapshot)
        self._maybe_store_predictive_alert(snapshot)
        self.storage.save_prediction_snapshot(snapshot)
        session_id = str(snapshot.get("session_id") or "")
        if session_id:
            self._session_latest_snapshots[session_id] = snapshot
            snapshot_history = self._session_prediction_snapshots.setdefault(session_id, [])
            snapshot_history.append(snapshot)
            try:
                history_limit = max(
                    1,
                    int((self.config.calibration_policy or {}).get("auto_evidence_snapshot_cache_limit", 25)),
                )
            except (TypeError, ValueError):
                history_limit = 25
            if len(snapshot_history) > history_limit:
                del snapshot_history[:-history_limit]

    def _on_session_end(self, state: Any) -> None:
        attach_runtime_context(state)
        self._apply_session_ttp_correlations(state)
        payload = self._session_payload(state)
        payload["status"] = "closed"
        mark_session_outcome(payload)
        self._apply_campaign_clustering(payload, "closed")
        record_sightings(self.storage, extract_session_observable_sightings(payload))
        enqueue_session_observables(self.storage, payload, enabled=self.config.enable_enrichment_jobs)
        skip_reason = ""
        if self.config.analysis_skip_empty_sessions:
            skip_reason = session_analysis_skip_reason(payload)
        if skip_reason:
            mark_session_analysis_skipped(payload, skip_reason)
            self.storage.save_session(payload)
            payload["threat_hunt_enqueue"] = enqueue_threat_hunts_for_session(
                self.storage,
                payload,
                self.config.threat_hunt_policy,
            )
            self.storage.save_session(payload)
            print(
                json.dumps(
                    {
                        "service": "session_worker",
                        "session_id": payload.get("session_id", "unknown"),
                        "analysis_status": "skipped",
                        "reason": skip_reason,
                        "timestamp": utc_now(),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            return
        job_id = self.storage.enqueue_analysis_job(payload)
        mark_session_analysis_queued(payload, job_id)
        self.storage.save_session(payload)
        payload["threat_hunt_enqueue"] = enqueue_threat_hunts_for_session(
            self.storage,
            payload,
            self.config.threat_hunt_policy,
        )
        self.storage.save_session(payload)
        self._try_generate_auto_evidence(payload)

    def _try_generate_auto_evidence(self, payload: Dict[str, Any]) -> None:
        """Generate auto-evidence feedback at session close using recent prediction snapshots.

        Uses an in-memory snapshot cache to avoid extra storage queries.
        Only generates a row when classification confidence meets the policy threshold.
        Errors are logged but never raise so session close is never blocked.
        """
        try:
            session_id = str(payload.get("session_id") or "")
            snapshots = self._session_prediction_snapshots.pop(session_id, [])
            latest_snapshot = self._session_latest_snapshots.pop(session_id, None)
            if not snapshots and latest_snapshot:
                snapshots = [latest_snapshot]
            if not snapshots:
                return
            min_confidence = float(
                (self.config.calibration_policy or {}).get("min_auto_evidence_confidence", 0.90)
            )
            for snapshot in reversed(snapshots):
                feedback = build_auto_evidence_feedback(
                    {"payload": snapshot},
                    payload,
                    min_confidence=min_confidence,
                )
                if feedback:
                    self.storage.record_analyst_feedback(feedback)
                    break
        except Exception as exc:
            print(
                json.dumps(
                    {
                        "service": "session_worker",
                        "warning": "auto_evidence_generation_failed",
                        "session_id": payload.get("session_id", "unknown"),
                        "error": _safe_exception_text(exc),
                        "timestamp": utc_now(),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )

    def _save_active_sessions(self) -> None:
        for state in self.monitor._sessions.values():
            if getattr(state, "is_ended", False):
                continue
            self._apply_session_ttp_correlations(state)
            payload = self._session_payload(state)
            payload.setdefault("status", "active")
            mark_session_outcome(payload)
            self._apply_campaign_clustering(payload, "active")
            self.storage.save_session(payload)

    def process_unprocessed(self) -> int:
        self._refresh_enrichment_cache()
        self._refresh_prediction_engine()
        rows = self.storage.fetch_unprocessed_events(self.config.worker_batch_size)
        processed = 0
        for row in rows:
            event = row["event"]
            record_sightings(
                self.storage,
                extract_event_observable_sightings(
                    event,
                    event_id=row["event_id"],
                    sensor_id=row.get("sensor_id", self.config.sensor_id),
                ),
            )
            enqueue_event_observables(self.storage, event, enabled=self.config.enable_enrichment_jobs)
            self.monitor.on_event(event)
            state = self.monitor.get_session(str(event.get("session", "unknown")))
            trigger_info = self._prediction_trigger_for_event(event)
            if state is not None and trigger_info.get("matched"):
                self._save_prediction_snapshot(
                    state,
                    event,
                    event_id=row["event_id"],
                    trigger_info=trigger_info,
                )
            self.storage.mark_event_processed(row["event_id"])
            processed += 1
        if processed:
            self._save_active_sessions()
        return processed

    def rebuild_from_events(self, limit: int = 100000) -> int:
        self.monitor = self._new_monitor()
        rows = self.storage.fetch_events(limit=limit)
        for row in rows:
            record_sightings(
                self.storage,
                extract_event_observable_sightings(
                    row["event"],
                    event_id=row["event_id"],
                    sensor_id=row.get("sensor_id", self.config.sensor_id),
                ),
            )
            self.monitor.on_event(row["event"])
            state = self.monitor.get_session(str(row["event"].get("session", "unknown")))
            trigger_info = self._prediction_trigger_for_event(row["event"])
            if state is not None and trigger_info.get("matched"):
                self._save_prediction_snapshot(
                    state,
                    row["event"],
                    event_id=row["event_id"],
                    trigger_info=trigger_info,
                )
            self.storage.mark_event_processed(row["event_id"])
        self._save_active_sessions()
        return len(rows)

    def run_forever(self) -> None:
        while True:
            processed = self.process_unprocessed()
            print(
                json.dumps(
                    {
                        "service": "session_worker",
                        "processed": processed,
                        "active_sessions": len(self.monitor._sessions),
                        "timestamp": utc_now(),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            time.sleep(self.config.worker_poll_seconds)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the session monitor worker.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--once", action="store_true", help="Process one batch and exit.")
    parser.add_argument("--rebuild", action="store_true", help="Replay stored events before processing new ones.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    worker = SessionWorker(config)
    if args.rebuild:
        count = worker.rebuild_from_events()
        print(json.dumps({"service": "session_worker", "rebuilt_events": count}, sort_keys=True), flush=True)
    if args.once:
        processed = worker.process_unprocessed()
        print(json.dumps({"service": "session_worker", "processed": processed}, sort_keys=True))
        return 0
    worker.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
