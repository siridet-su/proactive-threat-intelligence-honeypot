"""Narrow, additive controlled-live provenance bridge for the frozen release.

This module is intentionally a wrapper around the release's existing session
worker.  It is not a replacement worker and it does not change classifiers,
policies, thresholds, storage schemas, or prediction semantics.  The wrapper
derives ``e2e_test`` only from exact, server-owned sensor/source metadata and
suppresses prediction/analysis side effects for that provenance class.
"""

from __future__ import annotations

import ipaddress
import json
import os
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Optional

from production.workers import session_monitor as monitor_module
from production.workers import session_worker as worker_module


SESSION_SOURCE_PRODUCTION_LIVE = "production_live"
SESSION_SOURCE_E2E_TEST = "e2e_test"
PROVENANCE_MARKER = "CONTROLLED_SYNTHETIC_TEST"
SCHEMA_VERSION = "controlled_synthetic_provenance_binding.v1"


_ORIGINALS: Dict[str, Any] = {}
_CURRENT_WORKER: Optional[Any] = None


def _exact_text(value: Any) -> Optional[str]:
    """Return canonical text only when no normalization is required."""

    if not isinstance(value, str) or not value or value != value.strip():
        return None
    return value


def _validate_list(values: Any, field: str) -> List[str]:
    if not isinstance(values, list) or not values:
        raise ValueError(f"{field} must be a non-empty list")
    result: List[str] = []
    for value in values:
        text = _exact_text(value)
        if text is None or text in result:
            raise ValueError(f"{field} contains an invalid or duplicate identity")
        result.append(text)
    return result


def _load_binding() -> Dict[str, Any]:
    path = os.getenv(
        "CONTROLLED_PROVENANCE_CONFIG_FILE",
        "/etc/honeypot/controlled_provenance.json",
    )
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError):
        # Missing or unreadable binding disables only the controlled marker;
        # ordinary production sessions remain production_live.
        return {
            "enabled": False,
            "sensor_ids": [],
            "source_ips": [],
            "marker": PROVENANCE_MARKER,
        }
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("controlled provenance binding schema is invalid")
    marker = _exact_text(value.get("marker"))
    if marker != PROVENANCE_MARKER:
        raise RuntimeError("controlled provenance binding marker is invalid")
    sensor_ids = _validate_list(value.get("sensor_ids"), "sensor_ids")
    source_ips = _validate_list(value.get("source_ips"), "source_ips")
    for source_ip in source_ips:
        try:
            parsed = ipaddress.ip_address(source_ip)
        except ValueError as exc:
            raise RuntimeError("controlled provenance source IP is invalid") from exc
        if parsed.is_global:
            raise RuntimeError("controlled provenance source IP must not be global")
    return {
        "enabled": value.get("enabled") is True,
        "sensor_ids": sensor_ids,
        "source_ips": source_ips,
        "marker": marker,
    }


def _derive(binding: Dict[str, Any], sensor_id: Any, source_ip: Any) -> Dict[str, str]:
    sensor = _exact_text(sensor_id)
    source = _exact_text(source_ip)
    if (
        binding.get("enabled") is True
        and sensor in binding.get("sensor_ids", [])
        and source in binding.get("source_ips", [])
    ):
        return {
            "session_source": SESSION_SOURCE_E2E_TEST,
            "provenance_marker": PROVENANCE_MARKER,
        }
    return {"session_source": SESSION_SOURCE_PRODUCTION_LIVE, "provenance_marker": ""}


def _provenance_for_event(worker: Any, event: Dict[str, Any]) -> Dict[str, str]:
    return _derive(
        worker._controlled_binding,
        event.get("sensor_id") or event.get("sensor"),
        event.get("src_ip"),
    )


def _state_source(state: Any) -> str:
    metadata = getattr(state, "session_metadata", {})
    if not isinstance(metadata, dict):
        return ""
    return str(metadata.get("_trusted_session_source") or "")


def _is_controlled(state: Any) -> bool:
    return _state_source(state) == SESSION_SOURCE_E2E_TEST


def _bind_state(state: Any, provenance: Dict[str, str]) -> None:
    metadata = getattr(state, "session_metadata", None)
    if not isinstance(metadata, dict):
        metadata = {}
        setattr(state, "session_metadata", metadata)
    previous = str(metadata.get("_trusted_session_source") or "")
    source = provenance["session_source"]
    if previous and previous != source:
        raise ValueError("trusted session provenance mismatch")
    metadata["_trusted_session_source"] = source
    if source == SESSION_SOURCE_E2E_TEST:
        if provenance["provenance_marker"] != PROVENANCE_MARKER:
            raise ValueError("controlled synthetic provenance marker is invalid")
        metadata["_trusted_provenance_marker"] = PROVENANCE_MARKER
    elif metadata.get("_trusted_provenance_marker"):
        raise ValueError("non-synthetic session cannot carry a provenance marker")


def _suppressed() -> bool:
    worker = _CURRENT_WORKER
    if worker is None:
        return False
    current = getattr(worker, "_controlled_current_provenance", {})
    return bool(
        getattr(worker, "_controlled_close_active", False)
        or current.get("session_source") == SESSION_SOURCE_E2E_TEST
        or _is_controlled(getattr(worker, "_controlled_state", None))
    )


def _patch_runtime() -> None:
    global _CURRENT_WORKER
    if _ORIGINALS:
        return

    _ORIGINALS.update(
        {
            "monitor_on_event": monitor_module.SessionMonitor.on_event,
            "worker_init": worker_module.SessionWorker.__init__,
            "checkpoint": worker_module.SessionWorker._event_state_checkpoint,
            "durable_state": worker_module.SessionWorker._durable_state_for_event,
            "session_payload": worker_module.SessionWorker._session_payload,
            "predict_alert": worker_module.SessionWorker._predict_next_for_alert,
            "predict_unobserved": worker_module.SessionWorker._save_prediction_snapshot_unobserved,
            "predict_snapshot": worker_module.SessionWorker._save_prediction_snapshot,
            "campaign": worker_module.SessionWorker._apply_campaign_clustering,
            "close": worker_module.SessionWorker._on_session_end,
            "auto_evidence": worker_module.SessionWorker._try_generate_auto_evidence,
            "attach_context": worker_module.attach_runtime_context,
            "record_sightings": worker_module.record_sightings,
            "enqueue_event": worker_module.enqueue_event_observables,
            "enqueue_session": worker_module.enqueue_session_observables,
            "enqueue_hunts": worker_module.enqueue_threat_hunts_for_session,
        }
    )

    def patched_init(self: Any, config: Any) -> None:
        _ORIGINALS["worker_init"](self, config)
        self._controlled_binding = _load_binding()
        self._controlled_current_provenance = {
            "session_source": SESSION_SOURCE_PRODUCTION_LIVE,
            "provenance_marker": "",
        }
        self._controlled_state = None
        self._controlled_close_active = False

    def patched_checkpoint(self: Any, event: Dict[str, Any]) -> Any:
        global _CURRENT_WORKER
        _CURRENT_WORKER = self
        provenance = _provenance_for_event(self, event)
        self._controlled_current_provenance = provenance
        return _ORIGINALS["checkpoint"](self, event)

    def patched_durable_state(self: Any, session_id: str, event_id: str) -> Any:
        state = _ORIGINALS["durable_state"](self, session_id, event_id)
        if state is not None:
            _bind_state(state, self._controlled_current_provenance)
            self._controlled_state = state
        return state

    def patched_monitor_on_event(self: Any, event: Dict[str, Any], **kwargs: Any) -> Any:
        worker = _CURRENT_WORKER
        provenance = (
            _provenance_for_event(worker, event)
            if worker is not None
            else {"session_source": SESSION_SOURCE_PRODUCTION_LIVE, "provenance_marker": ""}
        )
        previous_alert_setting = getattr(self, "enable_alert_evaluation", True)
        if provenance["session_source"] == SESSION_SOURCE_E2E_TEST:
            self.enable_alert_evaluation = False
        try:
            result = _ORIGINALS["monitor_on_event"](self, event, **kwargs)
        finally:
            self.enable_alert_evaluation = previous_alert_setting
        session_id = str(event.get("session") or "")
        state = self.get_session(session_id) if session_id else None
        if state is not None:
            _bind_state(state, provenance)
            if worker is not None:
                worker._controlled_state = state
        return result

    def patched_session_payload(self: Any, state: Any) -> Dict[str, Any]:
        payload = _ORIGINALS["session_payload"](self, state)
        if _is_controlled(state):
            payload["session_source"] = SESSION_SOURCE_E2E_TEST
            payload["provenance_marker"] = PROVENANCE_MARKER
            payload["prediction_exclusion"] = {
                "excluded": True,
                "reason": "controlled_synthetic_test_not_prediction_evidence",
            }
            payload["prediction_trusted_history"] = []
            payload["prediction_trusted_history_manifest"] = {}
            payload["prediction_trusted_phase_count"] = 0
            payload["prediction_trusted_label_count"] = 0
            payload["prediction_audit_only_label_count"] = 0
        elif payload.get("provenance_marker"):
            raise ValueError("non-synthetic session cannot carry a provenance marker")
        return payload

    def patched_predict_alert(self: Any, state: Any) -> List[str]:
        if _is_controlled(state):
            return []
        return _ORIGINALS["predict_alert"](self, state)

    def patched_predict_unobserved(self: Any, state: Any, *args: Any, **kwargs: Any) -> bool:
        if _is_controlled(state):
            return False
        return _ORIGINALS["predict_unobserved"](self, state, *args, **kwargs)

    def patched_predict_snapshot(self: Any, state: Any, *args: Any, **kwargs: Any) -> bool:
        if _is_controlled(state):
            return False
        return _ORIGINALS["predict_snapshot"](self, state, *args, **kwargs)

    def patched_campaign(self: Any, payload: Dict[str, Any], status: str) -> Dict[str, Any]:
        if payload.get("session_source") == SESSION_SOURCE_E2E_TEST:
            summary = {
                "status": "excluded_controlled_synthetic_test",
                "queued": 0,
            }
            payload["campaign_summary"] = summary
            return summary
        return _ORIGINALS["campaign"](self, payload, status)

    def patched_auto_evidence(self: Any, payload: Dict[str, Any]) -> None:
        if payload.get("session_source") == SESSION_SOURCE_E2E_TEST:
            return
        return _ORIGINALS["auto_evidence"](self, payload)

    def patched_attach_context(state: Any) -> Any:
        prior = getattr(state, "session_metadata", {})
        trusted = {
            key: prior[key]
            for key in ("_trusted_session_source", "_trusted_provenance_marker")
            if isinstance(prior, dict) and key in prior
        }
        result = _ORIGINALS["attach_context"](state)
        metadata = getattr(state, "session_metadata", None)
        if isinstance(metadata, dict):
            metadata.update(trusted)
        return result

    def patched_record_sightings(*args: Any, **kwargs: Any) -> Any:
        if _suppressed():
            return 0
        return _ORIGINALS["record_sightings"](*args, **kwargs)

    def patched_enqueue_event(*args: Any, **kwargs: Any) -> Any:
        if _suppressed():
            return 0
        return _ORIGINALS["enqueue_event"](*args, **kwargs)

    def patched_enqueue_session(*args: Any, **kwargs: Any) -> Any:
        if _suppressed():
            return 0
        return _ORIGINALS["enqueue_session"](*args, **kwargs)

    def patched_enqueue_hunts(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        if _suppressed():
            return {"status": "excluded_controlled_synthetic_test", "queued": 0}
        return _ORIGINALS["enqueue_hunts"](*args, **kwargs)

    def patched_close(
        self: Any,
        state: Any,
        evidence_cutoff: Any = None,
    ) -> None:
        controlled = _is_controlled(state)
        if not controlled:
            return _ORIGINALS["close"](
                self, state, evidence_cutoff=evidence_cutoff
            )
        self._controlled_state = state
        self._controlled_close_active = True
        previous_enabled = getattr(self.config, "enable_enrichment_jobs", False)
        original_skip = worker_module.session_analysis_skip_reason
        try:
            self.config.enable_enrichment_jobs = False
            worker_module.session_analysis_skip_reason = (
                lambda _payload: "controlled_synthetic_test_excluded"
            )
            return _ORIGINALS["close"](
                self, state, evidence_cutoff=evidence_cutoff
            )
        finally:
            worker_module.session_analysis_skip_reason = original_skip
            self.config.enable_enrichment_jobs = previous_enabled
            self._controlled_close_active = False

    monitor_module.SessionMonitor.on_event = patched_monitor_on_event
    worker_module.SessionWorker.__init__ = patched_init
    worker_module.SessionWorker._event_state_checkpoint = patched_checkpoint
    worker_module.SessionWorker._durable_state_for_event = patched_durable_state
    worker_module.SessionWorker._session_payload = patched_session_payload
    worker_module.SessionWorker._predict_next_for_alert = patched_predict_alert
    worker_module.SessionWorker._save_prediction_snapshot_unobserved = patched_predict_unobserved
    worker_module.SessionWorker._save_prediction_snapshot = patched_predict_snapshot
    worker_module.SessionWorker._apply_campaign_clustering = patched_campaign
    worker_module.SessionWorker._on_session_end = patched_close
    worker_module.SessionWorker._try_generate_auto_evidence = patched_auto_evidence
    worker_module.attach_runtime_context = patched_attach_context
    worker_module.record_sightings = patched_record_sightings
    worker_module.enqueue_event_observables = patched_enqueue_event
    worker_module.enqueue_session_observables = patched_enqueue_session
    worker_module.enqueue_threat_hunts_for_session = patched_enqueue_hunts


def main(argv: Optional[List[str]] = None) -> int:
    _patch_runtime()
    return worker_module.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
