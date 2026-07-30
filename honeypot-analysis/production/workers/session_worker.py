"""Session monitor worker for queued Cowrie events."""

from __future__ import annotations

import argparse
import json
import threading
import time
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from production.enrichment.mitre_attack_loader import load_mitre_attack_db
from production.workers.session_monitor import SessionMonitor, SessionState
from production.enrichment.threat_feed_loader import load_threat_feeds

from production.classification.classification_pipeline import NotebookParityClassifier
from production.utils.config import ProductionConfig
from production.policies.data_lifecycle_policy import load_data_lifecycle_policy
from production.policies.alert_authority_policy import load_alert_authority_policy
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
from production.prediction.next_behavior_runtime import (
    MODE as TRANSFORMER_POC_MODE,
    FrozenTransformerPocPredictor,
    finalize_prediction_snapshot,
)
from production.prediction.evidence_cutoff import (
    make_evidence_cutoff,
    require_valid_evidence_cutoff,
)
from production.prediction.prediction_snapshot_contract import (
    PredictionSnapshotIntegrityError,
)
from production.prediction.external_vomm_artifact import load_external_vomm_artifact
from production.prediction.vomm_rollback import (
    MODE as VOMM_ROLLBACK_MODE,
    ValidatedVommRollbackPredictor,
    empty_transition_model,
)
from production.utils.runtime_context import attach_runtime_context
from production.utils.serialization import session_to_payload, stable_id, utc_now
from production.utils.service_lifecycle import ServiceLifecycle
from production.utils.http_security import safe_correlation_id
from production.prediction.session_features import build_session_features
from production.correlation.session_ttp_correlation import apply_session_ttp_correlations, load_knowledge as load_session_ttp_correlation_knowledge
from production.classification.securebert_classifier import load_securebert_classifier
from production.storage import open_storage
from production.storage.contract import EVENT_FAILURE_TYPES
from production.storage.session_provenance import (
    SESSION_SOURCE_PRODUCTION_LIVE,
    normalize_session_source,
)
from production.utils.feedback import build_auto_evidence_feedback
from production.utils.sensitive_data import (
    redact_for_artifact,
    redact_exception_for_log,
    redact_for_session_state,
)
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

WORKER_LEADER_SCOPE = "session-worker"


class WorkerError(RuntimeError):
    """Stable, non-sensitive base class for event lifecycle failures."""


class LeadershipLost(WorkerError):
    """Raised when this process no longer owns the session-worker lease."""


class LeaseExpired(WorkerError):
    """Raised when this process can no longer renew an event claim."""


class _EventLeaseHeartbeat:
    """Renew a claimed event while analytical callbacks are running."""

    def __init__(self, worker: "SessionWorker", row: Dict[str, Any]) -> None:
        self.worker = worker
        self.row = row
        self._stop = threading.Event()
        self._lost: Optional[type[WorkerError]] = None
        self._thread = threading.Thread(
            target=self._run,
            name="session-worker-event-heartbeat",
            daemon=True,
        )

    def __enter__(self) -> "_EventLeaseHeartbeat":
        self._thread.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self._stop.set()
        self._thread.join(timeout=max(1.0, self.worker.config.event_lease_heartbeat_seconds))

    def _run(self) -> None:
        interval = float(self.worker.config.event_lease_heartbeat_seconds)
        while not self._stop.wait(interval):
            try:
                self.worker._renew_claim(self.row)
            except LeadershipLost:
                self._lost = LeadershipLost
                return
            except LeaseExpired:
                self._lost = LeaseExpired
                return
            except Exception:
                # The main processing thread performs the authoritative renewal
                # and failure transition. Never persist or print exception text
                # from this best-effort heartbeat thread.
                self._lost = LeaseExpired
                return

    def check(self) -> None:
        if self._lost is not None:
            raise self._lost("event lifecycle lease was lost")


def _safe_exception_text(exc: BaseException) -> str:
    """Return a stable exception description without rendering its arguments."""

    return redact_exception_for_log(exc)


def alert_payload(alert: Any, *, triggering_event_id: str = "") -> Dict[str, Any]:
    """Normalize a historical alert payload without granting storage authority.

    Retained for deterministic historical-reader compatibility. Current workers
    never pass this result to ``store_alert``.
    """

    payload = dict(getattr(alert, "__dict__", alert))
    payload.setdefault(
        "alert_id",
        stable_id(
            "alert",
            {
                "session_id": payload.get("session_id", "unknown"),
                "alert_key": (
                    payload.get("alert_key")
                    or payload.get("reason")
                    or payload.get("severity")
                    or "observed_threshold"
                ),
                "triggering_event_id": str(triggering_event_id or ""),
            },
        ),
    )
    payload.setdefault("triggering_event_id", str(triggering_event_id or ""))
    payload.setdefault("created_at", utc_now())
    payload.setdefault("authority_display", "historical_legacy_alert")
    return payload


class _DisabledPredictionEngine:
    """Explicit no-op used when prediction is disabled by configuration."""

    enabled = False


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
        self.data_lifecycle_policy = load_data_lifecycle_policy(
            config.data_lifecycle_policy_path
        )
        self.alert_authority_policy = load_alert_authority_policy(
            config.alert_authority_policy_path
        )
        prediction_lifecycle = self.data_lifecycle_policy.document["entities"][
            "prediction_snapshots"
        ]
        if (
            config.prediction_snapshot_retention_days
            != prediction_lifecycle["minimum_age_days"]
            or config.prediction_snapshot_keep_latest_per_session
            is not prediction_lifecycle["preserve_latest_per_session"]
        ):
            raise RuntimeError(
                "runtime prediction retention does not match the exact "
                "data-lifecycle policy"
            )
        record_lifecycle_policy = getattr(
            self.storage, "record_data_lifecycle_policy", None
        )
        if not callable(record_lifecycle_policy):
            raise RuntimeError(
                "selected storage backend lacks lifecycle-policy provenance support"
            )
        record_lifecycle_policy(
            policy_id=self.data_lifecycle_policy.policy_id,
            policy_version=self.data_lifecycle_policy.version,
            policy_sha256=self.data_lifecycle_policy.sha256,
            effective_path=self.data_lifecycle_policy.path,
        )
        self.worker_owner = f"session-worker:{uuid.uuid4()}"
        self.worker_token = str(uuid.uuid4())
        self._leader_held = False
        self._current_event_effects: Optional[Dict[str, bool | int]] = None
        self._processing_event_id = ""
        self._last_recovered_active_sessions = 0
        self._prediction_generation_errors = 0
        self._events_processed_total = 0
        self._worker_started_at = time.monotonic()
        self.feeds = None
        self.mitre_db = None
        self.enrichment_db: Dict[str, Any] = {}
        self.external_artifact_validation: Dict[str, Any] = {
            "status": "unavailable",
            "valid": False,
            "reasons": ["external_artifact_not_loaded"],
        }
        self._session_latest_snapshots: Dict[str, Dict[str, Any]] = {}
        self._session_prediction_snapshots: Dict[str, List[Dict[str, Any]]] = {}
        self.bert_fn = load_securebert_classifier(config)
        self.classifier = None
        self.session_ttp_correlation_policy = self._load_session_ttp_correlation_policy()
        self.prediction_engine = self._new_prediction_engine()
        if config.enable_feed_loading:
            self.feeds = load_threat_feeds(
                cisa_cache_path=config.cisa_cache_path or None,
                sigma_cache_path=config.sigma_cache_path or None,
                allow_network_refresh=False,
            )
            self.mitre_db = load_mitre_attack_db(
                cache_path=config.mitre_attack_path or None,
                silent=True,
                allow_network_refresh=False,
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
        correlation_id = str(payload.get("last_applied_event_id") or "").strip()
        if correlation_id:
            payload["correlation_id"] = safe_correlation_id(
                correlation_id,
                stable_id(
                    "session-correlation",
                    {"session_id": payload.get("session_id") or "unknown"},
                ),
            )
        redacted = redact_for_session_state(payload)
        if not isinstance(redacted, dict):
            raise TypeError("session state redaction must return an object")
        return redacted

    def _record_event_effect(self, key: str, value: bool | int = True) -> None:
        effects = self._current_event_effects
        if effects is None:
            return
        if type(value) is bool:
            effects[key] = bool(effects.get(key, False)) or value
            return
        effects[key] = int(effects.get(key, 0)) + int(value)

    def _ensure_leadership(self) -> bool:
        newly_acquired = not self._leader_held
        try:
            if self._leader_held:
                held = self.storage.renew_worker_lease(
                    WORKER_LEADER_SCOPE,
                    self.worker_owner,
                    self.worker_token,
                    self.config.worker_leader_lease_seconds,
                )
            else:
                held = self.storage.acquire_worker_lease(
                    WORKER_LEADER_SCOPE,
                    self.worker_owner,
                    self.worker_token,
                    self.config.worker_leader_lease_seconds,
                )
        except Exception:
            self._leader_held = False
            raise
        self._leader_held = bool(held)
        if self._leader_held and newly_acquired:
            try:
                self._last_recovered_active_sessions = self._recover_active_sessions()
                print(
                    json.dumps(
                        {
                            "service": "session_worker",
                            "event": "active_session_recovery",
                            "recovered_active_sessions": self._last_recovered_active_sessions,
                            "timestamp": utc_now(),
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
            except Exception:
                try:
                    self.storage.release_worker_lease(
                        WORKER_LEADER_SCOPE,
                        self.worker_owner,
                        self.worker_token,
                    )
                except Exception:
                    pass
                self._leader_held = False
                raise
        return self._leader_held

    def _renew_claim(self, row: Dict[str, Any]) -> None:
        if not self._ensure_leadership():
            raise LeadershipLost("session worker leadership was lost")
        renewed = self.storage.renew_event_claim(
            row["event_id"],
            self.worker_owner,
            row["claim_token"],
            self.config.event_lease_seconds,
            leader_scope=WORKER_LEADER_SCOPE,
            leader_token=self.worker_token,
        )
        if not renewed:
            raise LeaseExpired("event claim could not be renewed")

    def _event_state_checkpoint(self, event: Dict[str, Any]) -> Dict[str, Any]:
        session_id = str(event.get("session", "unknown"))
        state = self.monitor._sessions.get(session_id)
        return {
            "session_id": session_id,
            "session_existed": state is not None,
            "session": deepcopy(state),
            "stats": deepcopy(self.monitor._stats),
            "campaign_profiles": (
                deepcopy(self.monitor.campaign_tracker._profiles)
                if self.monitor.campaign_tracker is not None
                else None
            ),
            "latest_existed": session_id in self._session_latest_snapshots,
            "latest": deepcopy(self._session_latest_snapshots.get(session_id)),
            "history_existed": session_id in self._session_prediction_snapshots,
            "history": deepcopy(self._session_prediction_snapshots.get(session_id)),
        }

    def _restore_event_state(self, checkpoint: Dict[str, Any]) -> None:
        session_id = checkpoint["session_id"]
        if checkpoint["session_existed"]:
            self.monitor._sessions[session_id] = checkpoint["session"]
        else:
            self.monitor._sessions.pop(session_id, None)
        self.monitor._stats = checkpoint["stats"]
        if self.monitor.campaign_tracker is not None:
            self.monitor.campaign_tracker._profiles = (
                checkpoint["campaign_profiles"] or []
            )
        if checkpoint["latest_existed"]:
            self._session_latest_snapshots[session_id] = checkpoint["latest"]
        else:
            self._session_latest_snapshots.pop(session_id, None)
        if checkpoint["history_existed"]:
            self._session_prediction_snapshots[session_id] = checkpoint["history"]
        else:
            self._session_prediction_snapshots.pop(session_id, None)

    def _session_state_from_payload(
        self,
        payload: Any,
        *,
        expected_session_id: str,
    ) -> SessionState:
        if not isinstance(payload, dict):
            raise WorkerError("active session recovery payload must be an object")
        try:
            safe_payload = redact_for_session_state(payload)
        except Exception:
            raise WorkerError("active session recovery redaction failed") from None
        if not isinstance(safe_payload, dict):
            raise WorkerError("active session recovery payload must remain an object")
        session_id = safe_payload.get("session_id")
        if not isinstance(session_id, str) or not session_id or session_id != expected_session_id:
            raise WorkerError("active session recovery session identity mismatch")
        src_ip = safe_payload.get("src_ip", "unknown")
        start_time = safe_payload.get("start_time", utc_now())
        if not isinstance(src_ip, str) or not isinstance(start_time, str):
            raise WorkerError("active session recovery scalar validation failed")
        state = SessionState(session_id=session_id, src_ip=src_ip, start_time=start_time)
        for field_name in state.__dataclass_fields__:
            if field_name not in safe_payload:
                continue
            value = safe_payload[field_name]
            default_value = getattr(state, field_name)
            if isinstance(default_value, list) and not isinstance(value, list):
                raise WorkerError("active session recovery list validation failed")
            if isinstance(default_value, dict) and not isinstance(value, dict):
                raise WorkerError("active session recovery mapping validation failed")
            if type(default_value) is bool and type(value) is not bool:
                raise WorkerError("active session recovery boolean validation failed")
            if type(default_value) is int and type(value) is not int:
                raise WorkerError("active session recovery integer validation failed")
            if type(default_value) is float and (
                type(value) not in {int, float}
            ):
                raise WorkerError("active session recovery number validation failed")
            if isinstance(default_value, str) and not isinstance(value, str):
                raise WorkerError("active session recovery text validation failed")
            setattr(state, field_name, deepcopy(value))
        return state

    @staticmethod
    def _payload_from_storage_row(row: Dict[str, Any]) -> Dict[str, Any]:
        payload = row.get("payload")
        if isinstance(payload, dict):
            return payload
        raw = row.get("payload_json")
        if isinstance(raw, dict):
            return raw
        if not isinstance(raw, str):
            raise WorkerError("durable session payload is missing")
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            raise WorkerError("durable session payload is invalid JSON") from None
        if not isinstance(decoded, dict):
            raise WorkerError("durable session payload must be an object")
        return decoded

    def _recalculate_monitor_stats(self) -> None:
        sessions = list(self.monitor._sessions.values())
        self.monitor._stats = {
            "events": sum(len(state.raw_events) for state in sessions),
            "alerts": sum(len(state.alerts_fired) for state in sessions),
            "sessions": len(sessions),
        }

    def _recover_prediction_cache(self, session_id: str) -> None:
        history_limit = 25
        rows = self.storage.list_prediction_snapshots_for_session(
            session_id,
            limit=history_limit,
        )
        snapshots: List[Dict[str, Any]] = []
        for row in reversed(rows):
            snapshot = self._payload_from_storage_row(row)
            redacted = redact_for_artifact(snapshot)
            if not isinstance(redacted, dict):
                raise WorkerError("prediction recovery payload must be an object")
            snapshots.append(redacted)
        if snapshots:
            self._session_prediction_snapshots[session_id] = snapshots
            current = self.storage.get_current_prediction_snapshot(session_id)
            if current is None:
                self._session_latest_snapshots.pop(session_id, None)
            else:
                self._session_latest_snapshots[session_id] = (
                    self._payload_from_storage_row(current)
                )
        else:
            self._session_prediction_snapshots.pop(session_id, None)
            self._session_latest_snapshots.pop(session_id, None)

    def _recover_active_sessions(self) -> int:
        limit = int(self.config.active_session_recovery_limit)
        rows = self.storage.list_active_session_rows(
            limit=limit + 1,
            session_source=self._session_source(),
        )
        if len(rows) > limit:
            raise WorkerError("active session recovery limit exceeded")
        self.monitor._sessions.clear()
        if self.monitor.campaign_tracker is not None:
            self.monitor.campaign_tracker._profiles.clear()
        self._session_latest_snapshots.clear()
        self._session_prediction_snapshots.clear()
        for row in rows:
            session_id = str(row.get("session_id") or "")
            state = self._session_state_from_payload(
                self._payload_from_storage_row(row),
                expected_session_id=session_id,
            )
            self.monitor._bound_session_history(state)
            if state.is_ended:
                raise WorkerError("active session recovery returned a closed session")
            self.monitor._sessions[session_id] = state
            self._recover_prediction_cache(session_id)
        self._recalculate_monitor_stats()
        return len(rows)

    def _durable_state_for_event(
        self,
        session_id: str,
        event_id: str,
    ) -> Optional[SessionState]:
        row = self.storage.get_session(session_id)
        if not row:
            return None
        payload = self._payload_from_storage_row(row)
        if payload.get("last_applied_event_id") != event_id:
            return None
        state = self._session_state_from_payload(
            payload,
            expected_session_id=session_id,
        )
        self.monitor._bound_session_history(state)
        self._recover_prediction_cache(session_id)
        return state

    def _retry_delay_seconds(self, attempts: int) -> float:
        exponent = min(max(int(attempts) - 1, 0), 31)
        return min(
            float(self.config.event_retry_max_seconds),
            float(self.config.event_retry_base_seconds) * (2**exponent),
        )

    @staticmethod
    def _failure_identity(exc: Exception) -> tuple[str, str, bool]:
        if isinstance(exc, LeadershipLost):
            return "stale_leader", "LeadershipLost", True
        if isinstance(exc, LeaseExpired):
            return "stale_worker", "LeaseExpired", True
        if isinstance(exc, (TypeError, ValueError)):
            return "event_processing_invalid", "ValidationError", False
        error_type = type(exc).__name__
        if error_type not in EVENT_FAILURE_TYPES:
            error_type = "Exception"
        return "event_processing_failed", error_type, True

    def close(self) -> None:
        if not self._leader_held:
            return
        try:
            self.storage.release_worker_lease(
                WORKER_LEADER_SCOPE,
                self.worker_owner,
                self.worker_token,
            )
        except Exception:
            pass
        finally:
            self._leader_held = False

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

    def _load_external_transition_model(self) -> Dict[str, Any]:
        policy = self.config.prediction_policy or {}
        path_text = str(policy.get("external_transition_model_path") or "").strip()
        manifest_path_text = str(policy.get("external_transition_manifest_path") or "").strip()
        if not path_text:
            self.external_artifact_validation = {
                "status": "unavailable",
                "valid": False,
                "reasons": ["external_transition_model_path_not_configured"],
            }
            return empty_transition_model()
        if not manifest_path_text:
            self.external_artifact_validation = {
                "status": "unavailable",
                "valid": False,
                "reasons": ["external_only_mode_requires_manifest_path"],
                "artifact_path": path_text,
            }
            return empty_transition_model()
        model, validation = load_external_vomm_artifact(
            path_text,
            manifest_path_text,
            expected_artifact_sha256=str(
                policy.get("external_transition_expected_artifact_sha256") or ""
            ),
            expected_model_id=str(
                policy.get("external_transition_expected_model_id") or ""
            ),
            expected_manifest_id=str(
                policy.get("external_transition_expected_manifest_id") or ""
            ),
        )
        self.external_artifact_validation = validation
        if validation.get("valid"):
            return model
        print(
            json.dumps(
                {
                    "service": "session_worker",
                    "warning": "external_vomm_artifact_unavailable",
                    "path": path_text,
                    "manifest_path": manifest_path_text,
                    "reasons": list(validation.get("reasons") or []),
                    "timestamp": utc_now(),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return empty_transition_model()

    def _new_prediction_engine(self) -> Any:
        policy = self.config.prediction_policy or {}
        if policy.get("enabled") is False:
            return _DisabledPredictionEngine()
        if str(policy.get("prediction_mode") or "") == TRANSFORMER_POC_MODE:
            return FrozenTransformerPocPredictor(self.config.prediction_policy)
        if str(policy.get("prediction_mode") or "") != VOMM_ROLLBACK_MODE:
            raise WorkerError(
                "prediction policy must select the frozen Transformer or explicit VOMM rollback"
            )
        return ValidatedVommRollbackPredictor(
            self.config.prediction_policy,
            model=self._load_external_transition_model(),
            artifact_validation=self.external_artifact_validation,
        )

    def _refresh_prediction_engine(self) -> None:
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
            on_alert=None,
            # The durable worker invokes the close stage explicitly after the
            # final close-event prediction has been persisted. SessionMonitor
            # retains callback support for standalone/legacy callers.
            on_session_end=None,
            classification_policy=self.config.classification_policy,
            credential_policy=self.config.credential_policy,
            credential_hasher=self.credential_hasher,
            campaign_profile_cache_limit=self.config.campaign_profile_cache_limit,
            session_event_history_limit=self.config.session_event_history_limit,
            enable_legacy_campaign_tracker=False,
            enable_alert_evaluation=(
                self.alert_authority_policy.automatic_alerts_authorized
            ),
        )

    def _refresh_enrichment_cache(self) -> None:
        self.enrichment_db = load_combined_ip_enrichment(
            storage=self.storage,
            file_path=self.config.enrichment_db_path,
            allow_stale=self.config.enrichment_allow_stale,
            local_max_bytes=self.config.local_enrichment_max_bytes,
            local_max_records=self.config.local_enrichment_max_records,
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
        """Compatibility callback that deliberately has no storage authority."""

        _ = alert

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

    def _maybe_store_predictive_alert(self, snapshot: Dict[str, Any]) -> None:
        """Persist the fixed advisory boundary; never evaluate alert thresholds."""

        snapshot["predictive_alert"] = {
            "schema_version": "predictive_alert_evaluation.v1",
            "enabled": False,
            "status": "prohibited",
            "reason": "prediction-only alert creation is prohibited",
            "suppressed_reasons": [
                "advisory next-behavior output has no alert authority"
            ],
            "legacy_candidate_thresholds_crossed": False,
            "authority": {
            "prediction_only": True,
            "may_create_alert": False,
            "may_escalate_enrichment": False,
                "semantics": "advisory_forecast_only",
            },
            "enrichment_escalation": {
                "status": "prohibited",
                "reason": "prediction alone cannot escalate enrichment",
            },
        }

    def _apply_campaign_clustering(self, payload: Dict[str, Any], status: str) -> Dict[str, Any]:
        try:
            summary = create_or_update_campaign(
                self.storage,
                payload,
                self.config.campaign_policy,
                status=status,
                alert_authority_policy=self.alert_authority_policy,
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
            self._record_event_effect("campaign_updated")
        return summary

    def _predict_next_for_alert(self, state: Any) -> List[str]:
        """Return alert text predictions from the production scorer engine.

        This keeps legacy realtime alerts aligned with the monitor/API output.
        It deliberately does not store a snapshot; the normal event path stores
        the durable prediction immediately after SessionMonitor.on_event().
        """
        if not self.prediction_engine.enabled:
            return []
        if isinstance(self.prediction_engine, FrozenTransformerPocPredictor):
            # The corrected-target PoC forecast is advisory and can never feed
            # the legacy realtime alert callback.
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

    def _save_prediction_snapshot_unobserved(
        self,
        state: Any,
        event: Dict[str, Any],
        event_id: str = "",
        trigger_info: Optional[Dict[str, Any]] = None,
        evidence_cutoff: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if not self.prediction_engine.enabled:
            return False
        if hasattr(self.monitor, "_apply_session_enrichment"):
            self.monitor._apply_session_enrichment(state)
        self._apply_session_ttp_correlations(state)
        payload = self._session_payload(state)
        payload.setdefault("status", "closed" if payload.get("is_ended") else "active")
        mark_session_outcome(payload)
        self._apply_campaign_clustering(payload, "closed" if payload.get("is_ended") else "active")
        safe_event = redact_for_artifact(event)
        if not isinstance(safe_event, dict):
            raise WorkerError("prediction trigger event redaction failed")
        cutoff = require_valid_evidence_cutoff(evidence_cutoff)
        if cutoff["event_id"] != str(event_id or ""):
            raise WorkerError(
                "prediction trigger event does not match evidence cutoff"
            )
        task = {
            "schema_version": "prediction_outbox_task.v2",
            "session_id": str(payload.get("session_id") or "unknown"),
            "event_id": str(event_id or ""),
            "evidence_cutoff": cutoff,
            "prediction_mode": str(
                self.config.prediction_policy.get("prediction_mode") or ""
            ),
            "session_payload": payload,
            "event": safe_event,
            "trigger": (
                trigger_info or self._prediction_trigger_for_event(event)
            ),
        }
        self.storage.enqueue_prediction_outbox(task)
        self._record_event_effect("prediction_outbox_enqueued")
        self._drain_prediction_outbox(limit=1)
        return True

    def _prediction_outbox_retry_delay(self, attempts: int) -> float:
        exponent = min(max(int(attempts) - 1, 0), 31)
        return min(
            float(self.config.prediction_outbox_retry_max_seconds),
            float(self.config.prediction_outbox_retry_base_seconds)
            * (2**exponent),
        )

    def _drain_prediction_outbox(self, *, limit: Optional[int] = None) -> int:
        if not hasattr(self.storage, "claim_prediction_outbox"):
            raise WorkerError("selected storage lacks prediction outbox support")
        claimed = self.storage.claim_prediction_outbox(
            self.worker_owner,
            int(limit or self.config.prediction_outbox_batch_size),
            self.config.prediction_outbox_lease_seconds,
            self.config.prediction_outbox_max_attempts,
        )
        completed = 0
        for row in claimed:
            try:
                task = row["task"]
                payload = task.get("session_payload")
                event = task.get("event")
                if not isinstance(payload, dict) or not isinstance(event, dict):
                    raise ValueError("prediction outbox task is invalid")
                event_id = str(task.get("event_id") or "")
                evidence_cutoff = task.get("evidence_cutoff")
                if evidence_cutoff is not None:
                    evidence_cutoff = require_valid_evidence_cutoff(
                        evidence_cutoff
                    )
                    if evidence_cutoff["event_id"] != event_id:
                        raise ValueError(
                            "prediction task cutoff does not match event_id"
                        )
                if isinstance(
                    self.prediction_engine, FrozenTransformerPocPredictor
                ):
                    snapshot = self.prediction_engine.predict_session(
                        payload,
                        event_id=event_id,
                        evidence_cutoff=evidence_cutoff,
                    )
                else:
                    features = build_session_features(
                        payload, current_event=event
                    )
                    snapshot = self.prediction_engine.predict(
                        features, event_id=event_id
                    )
                    if evidence_cutoff is not None:
                        snapshot["evidence_cutoff"] = evidence_cutoff
                snapshot["prediction_trigger"] = task.get("trigger") or {}
                snapshot["predictive_alert"] = {
                    "status": "prohibited",
                    "reason": "prediction alone cannot create an alert",
                }
                if isinstance(
                    self.prediction_engine, FrozenTransformerPocPredictor
                ):
                    snapshot = finalize_prediction_snapshot(snapshot)
                snapshot_id = self.storage.save_prediction_snapshot(snapshot)
                if not self.storage.complete_prediction_outbox(
                    row["outbox_id"],
                    row["claim_owner"],
                    row["claim_token"],
                    snapshot_id,
                ):
                    raise LeaseExpired("prediction outbox completion lost claim")
                self._record_event_effect("prediction_saved")
                session_id = str(snapshot.get("session_id") or "")
                if session_id:
                    self._recover_prediction_cache(session_id)
                completed += 1
            except Exception as exc:
                self._prediction_generation_errors += 1
                error_type = type(exc).__name__
                retryable = not isinstance(exc, (TypeError, ValueError))
                error_code = (
                    "prediction_snapshot_integrity_error"
                    if isinstance(exc, PredictionSnapshotIntegrityError)
                    else "prediction_generation_failed"
                )
                self.storage.fail_prediction_outbox(
                    row["outbox_id"],
                    row["claim_owner"],
                    row["claim_token"],
                    error_code,
                    error_type,
                    retryable,
                    self.config.prediction_outbox_max_attempts,
                    self._prediction_outbox_retry_delay(
                        int(row.get("attempts") or 1)
                    ),
                )
                print(
                    json.dumps(
                        {
                            "service": "session_worker",
                            "event": "prediction_outbox_failed",
                            "outbox_id": row.get("outbox_id"),
                            "error": _safe_exception_text(exc),
                            "timestamp": utc_now(),
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
        return completed

    def _save_prediction_snapshot(
        self,
        state: Any,
        event: Dict[str, Any],
        event_id: str = "",
        trigger_info: Optional[Dict[str, Any]] = None,
        evidence_cutoff: Optional[Dict[str, Any]] = None,
    ) -> bool:
        try:
            return self._save_prediction_snapshot_unobserved(
                state,
                event,
                event_id=event_id,
                trigger_info=trigger_info,
                evidence_cutoff=evidence_cutoff,
            )
        except Exception as exc:
            self._prediction_generation_errors += 1
            print(
                json.dumps(
                    {
                        "service": "session_worker",
                        "event": "prediction_generation_failed",
                        "correlation_id": event_id,
                        "prediction_generation_errors": self._prediction_generation_errors,
                        "error": _safe_exception_text(exc),
                        "timestamp": utc_now(),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            raise

    def _on_session_end(self, state: Any) -> None:
        if self._processing_event_id:
            state.last_applied_event_id = self._processing_event_id
        attach_runtime_context(state)
        self._apply_session_ttp_correlations(state)
        payload = self._session_payload(state)
        payload["status"] = "closed"
        durable_snapshot = self.storage.load_session_event_snapshot(
            str(payload.get("session_id") or ""),
            self._processing_event_id,
            self.config.canonical_evidence_max_events,
        )
        payload["canonical_event_manifest"] = {
            key: durable_snapshot[key]
            for key in (
                "schema_version",
                "session_id",
                "through_event_id",
                "event_count",
                "manifest_sha256",
            )
        }
        mark_session_outcome(payload)
        self._apply_campaign_clustering(payload, "closed")
        self._record_event_effect(
            "observable_sightings_recorded",
            record_sightings(self.storage, extract_session_observable_sightings(payload)),
        )
        self._record_event_effect(
            "enrichment_jobs_enqueued",
            enqueue_session_observables(
                self.storage,
                payload,
                enabled=self.config.enable_enrichment_jobs,
            ),
        )
        skip_reason = ""
        if self.config.analysis_skip_empty_sessions:
            skip_reason = session_analysis_skip_reason(payload)
        if skip_reason:
            mark_session_analysis_skipped(payload, skip_reason)

        # Durable close order: prediction persistence happens in the caller;
        # persist the finalized closed session before making work visible.
        self.storage.save_session(payload)
        self._record_event_effect("session_saved")

        if skip_reason:
            self.storage.update_session_analysis_status(
                str(payload.get("session_id") or ""),
                "skipped",
                skip_reason=skip_reason,
            )
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
        else:
            job_id = self.storage.enqueue_analysis_job(payload)
            self._record_event_effect("analysis_job_enqueued")
            mark_session_analysis_queued(payload, job_id)
            self.storage.update_session_analysis_status(
                str(payload.get("session_id") or ""),
                "queued",
                job_id=job_id,
            )

        payload["threat_hunt_enqueue"] = enqueue_threat_hunts_for_session(
            self.storage,
            payload,
            self.config.threat_hunt_policy,
        )
        self._record_event_effect(
            "threat_hunt_jobs_enqueued",
            int(payload["threat_hunt_enqueue"].get("queued") or 0),
        )
        self.storage.save_session(payload)
        self._record_event_effect("session_saved")
        self._record_event_effect("session_closed")
        if not skip_reason:
            self._try_generate_auto_evidence(payload)

    def _try_generate_auto_evidence(self, payload: Dict[str, Any]) -> None:
        """Generate auto-evidence feedback at session close using recent prediction snapshots.

        Uses an in-memory snapshot cache to avoid extra storage queries.
        Only generates a row when classification confidence meets the policy threshold.
        Errors are logged but never raise so session close is never blocked.
        """
        try:
            session_id = str(payload.get("session_id") or "")
            self._recover_prediction_cache(session_id)
            snapshots = self._session_prediction_snapshots.pop(session_id, [])
            latest_snapshot = self._session_latest_snapshots.pop(session_id, None)
            if not snapshots and latest_snapshot:
                snapshots = [latest_snapshot]
            if not snapshots:
                return
            min_confidence = 0.90
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

    def _save_active_session(self, state: Any) -> None:
        if getattr(state, "is_ended", False):
            return
        self._apply_session_ttp_correlations(state)
        payload = self._session_payload(state)
        payload.setdefault("status", "active")
        mark_session_outcome(payload)
        self._apply_campaign_clustering(payload, "active")
        self.storage.save_session(payload)
        self._record_event_effect("session_saved")

    def _save_active_sessions(self) -> None:
        for state in self.monitor._sessions.values():
            self._save_active_session(state)

    def process_unprocessed(
        self,
        *,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> int:
        if should_stop is not None and should_stop():
            return 0
        if not self._ensure_leadership():
            return 0
        self._refresh_enrichment_cache()
        self._drain_prediction_outbox()
        processed = 0
        attempted = 0
        prediction_refreshed = False
        while attempted < self.config.worker_batch_size:
            if should_stop is not None and should_stop():
                break
            if not self._ensure_leadership():
                break
            rows = self.storage.claim_events(
                self.worker_owner,
                1,
                self.config.event_lease_seconds,
                max_attempts=self.config.event_max_attempts,
                leader_scope=WORKER_LEADER_SCOPE,
                leader_token=self.worker_token,
            )
            if not rows:
                break
            row = rows[0]
            if should_stop is not None and should_stop():
                self.storage.release_event_claim(
                    row["event_id"],
                    self.worker_owner,
                    row["claim_token"],
                    leader_scope=WORKER_LEADER_SCOPE,
                    leader_token=self.worker_token,
                )
                break
            if not prediction_refreshed:
                self._refresh_prediction_engine()
                prediction_refreshed = True
            attempted += 1
            event = row["event"]
            evidence_cutoff = make_evidence_cutoff(
                row.get("received_at"),
                row["event_id"],
            )
            checkpoint = self._event_state_checkpoint(event)
            effects: Dict[str, bool | int] = {}
            self._current_event_effects = effects
            self._processing_event_id = row["event_id"]
            try:
                with _EventLeaseHeartbeat(self, row) as heartbeat:
                    self._record_event_effect(
                        "observable_sightings_recorded",
                        record_sightings(
                            self.storage,
                            extract_event_observable_sightings(
                                event,
                                event_id=row["event_id"],
                                sensor_id=row.get("sensor_id", self.config.sensor_id),
                            ),
                        ),
                    )
                    self._record_event_effect(
                        "enrichment_jobs_enqueued",
                        enqueue_event_observables(
                            self.storage,
                            event,
                            enabled=self.config.enable_enrichment_jobs,
                        ),
                    )
                    self._renew_claim(row)
                    heartbeat.check()
                    session_id = str(event.get("session", "unknown"))
                    state = self._durable_state_for_event(
                        session_id,
                        row["event_id"],
                    )
                    if state is not None:
                        self.monitor._sessions[session_id] = state
                        self._recalculate_monitor_stats()
                        self._record_event_effect("event_applied")
                        if state.is_ended:
                            trigger_info = self._prediction_trigger_for_event(event)
                            latest = self._session_latest_snapshots.get(session_id) or {}
                            if (
                                trigger_info.get("matched")
                                and latest.get("event_id") != row["event_id"]
                            ):
                                self._save_prediction_snapshot(
                                    state,
                                    event,
                                    event_id=row["event_id"],
                                    trigger_info=trigger_info,
                                    evidence_cutoff=evidence_cutoff,
                                )
                            self._on_session_end(state)
                        else:
                            self._save_active_session(state)
                    else:
                        self.monitor.on_event(event)
                        self._record_event_effect("event_applied")
                        state = self.monitor.get_session(session_id)
                        if state is not None and not getattr(state, "is_ended", False):
                            state.last_applied_event_id = row["event_id"]
                        trigger_info = self._prediction_trigger_for_event(event)
                        if state is not None and trigger_info.get("matched"):
                            self._save_prediction_snapshot(
                                state,
                                event,
                                event_id=row["event_id"],
                                trigger_info=trigger_info,
                                evidence_cutoff=evidence_cutoff,
                            )
                        if state is not None:
                            if getattr(state, "is_ended", False):
                                self._on_session_end(state)
                            else:
                                self._save_active_session(state)
                    self._renew_claim(row)
                    heartbeat.check()
                    if not self.storage.complete_event(
                        row["event_id"],
                        self.worker_owner,
                        row["claim_token"],
                        effects,
                        leader_scope=WORKER_LEADER_SCOPE,
                        leader_token=self.worker_token,
                    ):
                        raise LeaseExpired("event completion lost its claim")
                processed += 1
            except Exception as exc:
                self._restore_event_state(checkpoint)
                error_code, error_type, retryable = self._failure_identity(exc)
                try:
                    failure_status = self.storage.fail_event(
                        row["event_id"],
                        self.worker_owner,
                        row["claim_token"],
                        error_code,
                        error_type,
                        retryable,
                        self.config.event_max_attempts,
                        self._retry_delay_seconds(int(row.get("attempts") or 1)),
                        leader_scope=WORKER_LEADER_SCOPE,
                        leader_token=self.worker_token,
                    )
                except Exception:
                    failure_status = "failure_transition_unavailable"
                print(
                    json.dumps(
                        {
                            "service": "session_worker",
                            "event_id": row["event_id"],
                            "correlation_id": row["event_id"],
                            "event_status": failure_status,
                            "error_code": error_code,
                            "error_type": error_type,
                            "attempts": int(row.get("attempts") or 1),
                            "timestamp": utc_now(),
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
                if isinstance(exc, LeadershipLost):
                    break
            finally:
                self._current_event_effects = None
                self._processing_event_id = ""
        return processed

    def _evict_closed_sessions(self) -> int:
        """Drop closed states only at a completed long-running loop boundary."""

        closed = [
            session_id
            for session_id, state in self.monitor._sessions.items()
            if getattr(state, "is_ended", False)
        ]
        for session_id in closed:
            self.monitor._sessions.pop(session_id, None)
            self._session_latest_snapshots.pop(session_id, None)
            self._session_prediction_snapshots.pop(session_id, None)
        return len(closed)

    def rebuild_from_events(self, limit: int = 100000) -> int:
        del limit  # Compatibility argument; recovery uses the validated config bound.
        if not self._ensure_leadership():
            return 0
        return len(self.monitor._sessions)

    def run_forever(self, lifecycle: Optional[ServiceLifecycle] = None) -> None:
        control = lifecycle or ServiceLifecycle()
        try:
            with control.signal_handlers():
                while not control.stopping:
                    processed = self.process_unprocessed(
                        should_stop=lambda: control.stopping
                    )
                    evicted_closed_sessions = self._evict_closed_sessions()
                    if processed:
                        self._events_processed_total += processed
                        elapsed = max(time.monotonic() - self._worker_started_at, 0.001)
                        print(
                            json.dumps(
                                {
                                    "service": "session_worker",
                                    "processed": processed,
                                    "active_sessions": len(self.monitor._sessions),
                                    "evicted_closed_sessions": evicted_closed_sessions,
                                    "recovered_active_sessions": self._last_recovered_active_sessions,
                                    "event_processing_rate_per_second": round(
                                        self._events_processed_total / elapsed,
                                        6,
                                    ),
                                    "prediction_generation_errors": self._prediction_generation_errors,
                                    "timestamp": utc_now(),
                                },
                                sort_keys=True,
                            ),
                            flush=True,
                        )
                    control.wait(self.config.worker_poll_seconds)
        finally:
            self.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the session monitor worker.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--once", action="store_true", help="Process one batch and exit.")
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Reload durable active-session snapshots before processing new events.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    worker = SessionWorker(config)
    try:
        if args.rebuild:
            count = worker.rebuild_from_events()
            print(
                json.dumps(
                    {"service": "session_worker", "recovered_active_sessions": count},
                    sort_keys=True,
                ),
                flush=True,
            )
        if args.once:
            processed = worker.process_unprocessed()
            print(json.dumps({"service": "session_worker", "processed": processed}, sort_keys=True))
            return 0
        worker.run_forever()
        return 0
    finally:
        worker.close()


if __name__ == "__main__":
    raise SystemExit(main())
