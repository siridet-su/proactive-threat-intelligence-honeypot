"""Dashboard API for operator visibility and analyst feedback."""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from production.utils.config import ProductionConfig
from production.prediction.prediction_health import infer_prediction_paths, load_prediction_health
from production.prediction_next_distinct_poc.dashboard_adapter import build_dashboard_prediction
from production.classification.classification_evaluation import classification_metrics
from production.reporting.feedback_review import FEEDBACK_FILTERS, build_feedback_review, filter_feedback_rows
from production.utils.feedback import normalize_submitted_feedback_payload
from production.utils.http_security import (
    BoundedThreadingHTTPServer,
    HTTPBodyError,
    decode_strict_json_body,
    is_loopback_host,
    read_bounded_http_body,
    safe_request_id,
    single_header_value,
    validate_bind_auth,
)
from production.utils.serialization import utc_now
from production.utils.service_lifecycle import serve_http_until_stopped
from production.reporting.response_guidance_v3 import (
    build_response_guidance_v3_from_session,
    validate_response_guidance_v3,
)
from production.storage import open_storage
from production.api.security import (
    api_row_view,
    authorize_read,
    authorize_write,
    log_payload,
    public_payload,
    sanitize_request_target,
    validate_configured_bearer_tokens,
)
from production.correlation.semantics import resolve_confidence_semantics


TABLES = {
    "/events": "events",
    "/sessions": "sessions",
    "/alerts": "alerts",
    "/jobs": "analysis_jobs",
    "/reports": "reports",
    "/feed-status": "feed_status",
    "/enrichment-records": "enrichment_records",
    "/enrichment-jobs": "enrichment_jobs",
    "/prediction-snapshots": "prediction_snapshots",
    "/prediction-backtests": "prediction_backtest_runs",
    "/prediction-calibrations": "prediction_calibration_runs",
    "/analyst-feedback": "analyst_feedback",
    "/classification-review-labels": "classification_review_labels",
    "/observables": "observables",
    "/observable-sightings": "observable_sightings",
    "/threat-hunt-jobs": "threat_hunt_jobs",
    "/session-links": "session_links",
    "/campaigns": "campaigns",
    "/campaign-sessions": "campaign_sessions",
    "/webhooks": "webhook_deliveries",
}
MAX_FEEDBACK_BODY_BYTES = 1_000_000
FEEDBACK_REQUEST_TIMEOUT_SECONDS = 15.0


def _feedback_summary(rows: list[Dict[str, Any]]) -> Dict[str, Any]:
    labels: Dict[str, int] = {}
    types: Dict[str, int] = {}
    operator_signals: Dict[str, int] = {}
    action_statuses: Dict[str, int] = {}
    weight_eligible = 0
    latest = ""
    for row in rows:
        label = str(row.get("label") or "unknown")
        labels[label] = labels.get(label, 0) + 1
        feedback_type = str(row.get("feedback_type") or "legacy")
        types[feedback_type] = types.get(feedback_type, 0) + 1
        operator_signal = str(row.get("operator_signal") or "")
        if operator_signal:
            operator_signals[operator_signal] = operator_signals.get(operator_signal, 0) + 1
        action_status = str(row.get("action_status") or "")
        if action_status:
            action_statuses[action_status] = action_statuses.get(action_status, 0) + 1
        if bool(row.get("weight_eligible")):
            weight_eligible += 1
        created_at = str(row.get("created_at") or "")
        if created_at > latest:
            latest = created_at
    return {
        "count": len(rows),
        "labels": labels,
        "feedback_types": types,
        "operator_signals": operator_signals,
        "action_statuses": action_statuses,
        "weight_eligible": weight_eligible,
        "latest_created_at": latest,
    }


def _current_prediction_payload(snapshot: Dict[str, Any], feedback_rows: list[Dict[str, Any]]) -> Dict[str, Any]:
    payload = snapshot.get("payload") or {}
    features = payload.get("features") or {}
    raw_correlations = features.get("session_ttp_correlations") or []
    correlations = []
    for item in raw_correlations:
        if not isinstance(item, dict):
            continue
        projected = dict(item)
        projected["confidence_semantics"] = resolve_confidence_semantics(
            item.get("confidence_semantics")
        )
        correlations.append(projected)
    raw_summary = features.get("session_ttp_correlation_summary") or {}
    correlation_summary = dict(raw_summary) if isinstance(raw_summary, dict) else {}
    correlation_summary["confidence_semantics"] = resolve_confidence_semantics(
        correlation_summary.get("confidence_semantics") or payload.get("confidence_semantics")
    )
    final_ranking = payload.get("final_ranking") or []
    source_breakdown: Dict[str, Dict[str, Any]] = {}
    for item in final_ranking:
        if not isinstance(item, dict):
            continue
        for source in item.get("sources") or []:
            if not isinstance(source, dict):
                continue
            name = str(source.get("name") or "unknown")
            entry = source_breakdown.setdefault(
                name,
                {
                    "source_type": source.get("source_type") or "",
                    "weighted_score_sum": 0.0,
                    "hypothesis_count": 0,
                },
            )
            entry["weighted_score_sum"] = round(float(entry["weighted_score_sum"]) + float(source.get("weighted_score") or 0.0), 4)
            entry["hypothesis_count"] += 1
    return {
        "snapshot_id": payload.get("snapshot_id") or snapshot.get("snapshot_id"),
        "snapshot_sha256": payload.get("snapshot_sha256") or "",
        "session_id": payload.get("session_id") or snapshot.get("session_id"),
        "generated_at": payload.get("generated_at") or snapshot.get("created_at"),
        "final_ranking": final_ranking,
        "prediction": payload.get("prediction") or [],
        "prediction_status": payload.get("prediction_status") or ("predicted" if final_ranking else "abstained"),
        "prediction_status_reason": payload.get("prediction_status_reason") or "",
        "source_breakdown": source_breakdown,
        "local_transition_model": payload.get("local_transition_model") or payload.get("model_maturity") or {},
        "external_seed_model": payload.get("external_seed_model") or {},
        "classification_quality": payload.get("classification_quality") or {},
        "session_ttp_correlations": correlations,
        "observed_trusted_ttps": features.get("observed_trusted_ttps") or [],
        "correlated_ttp_hypotheses": features.get(
            "correlated_ttp_hypotheses"
        ) or correlations,
        "session_ttp_correlation_summary": correlation_summary,
        "session_evidence_graph_summary": features.get("session_evidence_graph_summary") or {},
        "calibration_status": payload.get("calibration_status") or {},
        "weight_calibration": payload.get("weight_calibration") or {},
        "trust_status": payload.get("trust_status") or {},
        "agreement": payload.get("agreement") or {},
        "coverage": payload.get("coverage") or {},
        "confidence_damping": payload.get("confidence_damping") or {},
        "prediction_trigger": payload.get("prediction_trigger") or {},
        "evidence_cutoff": payload.get("evidence_cutoff") or {},
        "predictive_alert": payload.get("predictive_alert") or {},
        "prediction_mode": payload.get("prediction_mode") or "",
        "external_artifact": payload.get("external_artifact") or {},
        "local_shadow_prediction": payload.get("local_shadow_prediction") or {},
        "generic_progression_prior": payload.get("generic_progression_prior") or {},
        "weight_influence_scope": payload.get("weight_influence_scope") or "",
        "ranking_influence": payload.get("ranking_influence") or {},
        "prediction_contract": payload.get("prediction_contract") or "",
        "active_model": payload.get("active_model") or {},
        "next_behavior_output": payload.get("next_behavior_output") or {},
        "authority": payload.get("authority") or {},
        "deployment_decision": payload.get("deployment_decision") or "",
        "original_selection_status": payload.get("original_selection_status") or "",
        "runtime": payload.get("runtime") or {},
        "effective_weights": payload.get("effective_weights") or {},
        "active_weights": payload.get("active_weights") or {},
        "active_scorers": payload.get("active_scorers") or [],
        "external_seed_weight_policy": payload.get("external_seed_weight_policy") or {},
        "feedback_summary": _feedback_summary(feedback_rows),
    }


def _payload_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = row.get("payload")
    if isinstance(payload, dict):
        return payload
    try:
        loaded = json.loads(str(row.get("payload_json") or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    return loaded if isinstance(loaded, dict) else {}


def _session_payload_for_id(storage: Any, session_id: str) -> Dict[str, Any]:
    row = storage.get_session(session_id)
    if row:
        payload = _payload_from_row(row)
        payload.setdefault("session_id", session_id)
        payload.setdefault("src_ip", row.get("src_ip") or "unknown")
        return payload
    return {"session_id": session_id}


def _current_decision_payload(
    config: ProductionConfig,
    storage: Any,
    session_id: str,
    snapshot: Dict[str, Any],
    *,
    report_recommendations: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if not config.enable_response_guidance:
        return {"enabled": False, "reason": "response guidance layer disabled"}
    # Current decisions are a presentation of the stored report.  Rebuilding
    # from the mutable session row here would silently move the durable
    # evidence prefix forward and make the displayed identity ambiguous.
    report = None
    getter = getattr(storage, "get_current_report_for_session", None)
    if callable(getter):
        try:
            report = getter(session_id)
        except Exception:
            report = None
    report_payload = _payload_from_row(report or {}) if isinstance(report, dict) else {}
    stored = report_payload.get("response_guidance_v3")
    assessment_id = str(report_payload.get("assessment_id") or "")
    if not isinstance(stored, dict):
        return _unverified_guidance_payload(
            session_id,
            ["stored response guidance is unavailable"],
        )
    errors = validate_response_guidance_v3(
        stored,
        expected_session_id=session_id,
        expected_assessment_id=assessment_id,
    )
    binding = stored.get("binding") or {}
    if not errors and binding.get("status") == "verified":
        guidance = json.loads(json.dumps(stored))
        guidance["presentation_semantics"] = {
            "mode": "stored_durable_prefix_bound",
            "historical_record": False,
            "stored_report": True,
            "recomputed": False,
            "replaces_stored_historical_guidance": False,
            "description": (
                "Displayed guidance is the stored output bound to the report's "
                "durable evidence prefix, assessment, graph, policy, and output identity."
            ),
        }
        return guidance
    return _unverified_guidance_payload(
        session_id,
        errors or ["stored guidance binding is not fully verified"],
        assessment_id=assessment_id,
    )


def _unverified_guidance_payload(
    session_id: str,
    errors: list[str],
    *,
    assessment_id: str = "",
) -> Dict[str, Any]:
    """Return a deterministic, non-actionable response for unverified data."""

    return {
        "schema_version": "response_guidance.v3",
        "status": "unavailable",
        "guidance_state": "stored_guidance_unverified",
        "authority": "policy_unavailable",
        "session_id": str(session_id or "unknown"),
        "findings": [],
        "triage": {
            "review_priority": "info",
            "urgency": "routine_review",
            "semantics": "unverified_stored_guidance_not_actionable",
            "finding_ids": [],
        },
        "advisory_actions": [],
        "safety": {
            "automatic_execution": False,
            "manual_approval_required": True,
            "alerting_side_effect": False,
            "response_action_side_effect": False,
            "execution_integration": "not_implemented",
        },
        "binding": {
            "schema_version": "response_guidance_binding.v1",
            "status": "unverified",
            "session_id": str(session_id or "unknown"),
            "assessment": {"status": "unverified", "assessment_id": assessment_id},
            "validation_errors": list(errors),
        },
        "validation": {"status": "rejected", "errors": list(errors)},
        "presentation_semantics": {
            "mode": "stored_guidance_unverified",
            "historical_record": False,
            "stored_report": bool(assessment_id),
            "recomputed": False,
            "replaces_stored_historical_guidance": False,
            "description": "Stored guidance was not presented as verified or actionable.",
        },
    }


def _external_seed_health_payload(config: ProductionConfig) -> Dict[str, Any]:
    paths = infer_prediction_paths(config.prediction_policy)
    return load_prediction_health(
        paths["health"],
        model_path=paths["model"],
        validation_path=paths["validation"],
        review_path=paths["review"],
        include_review=False,
        mode=paths["mode"],
    )


class DashboardHandler(BaseHTTPRequestHandler):
    config: ProductionConfig

    def _storage(self):
        """Reuse the process-initialized adapter without rerunning migrations."""

        server = getattr(self, "server", None)
        storage = getattr(server, "storage", None)
        if storage is not None:
            return storage
        # Direct unit-test handlers have no server. Keep that narrow testing
        # seam while production always receives the initialized adapter.
        settings = getattr(self.config, "database_settings", None)
        return open_storage(
            settings() if callable(settings) else self.config.database_url
        )

    def _request_id(self) -> str:
        current = getattr(self, "_dashboard_request_id", "")
        if current:
            return str(current)
        headers = getattr(self, "headers", None)
        request_id = safe_request_id(
            headers.get("X-Request-ID") if headers is not None else None
        )
        self._dashboard_request_id = request_id
        return request_id

    def _send_json(self, status: HTTPStatus, payload: Dict[str, Any]) -> None:
        body = json.dumps(
            public_payload(payload),
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.send_header("X-Request-ID", self._request_id())
        self.end_headers()
        self.wfile.write(body)

    def _require_read(self) -> bool:
        read_token = str(getattr(self.config, "dashboard_read_token", "") or "")
        decision = authorize_read(
            single_header_value(self.headers, "Authorization"),
            read_token,
            allow_anonymous=(
                not read_token
                and is_loopback_host(str(getattr(self.config, "dashboard_host", "")))
            ),
        )
        if decision.allowed:
            return True
        self._send_json(
            decision.status,
            {"error": decision.error, "request_id": self._request_id()},
        )
        return False

    def _require_write(self) -> bool:
        decision = authorize_write(
            single_header_value(self.headers, "Authorization"),
            str(getattr(self.config, "dashboard_read_token", "") or ""),
            str(getattr(self.config, "dashboard_write_token", "") or ""),
        )
        if decision.allowed:
            return True
        self._send_json(
            decision.status,
            {"error": decision.error, "request_id": self._request_id()},
        )
        return False

    def _read_json_body(self) -> Dict[str, Any]:
        body = read_bounded_http_body(
            self.headers,
            self.rfile,
            max_body_bytes=MAX_FEEDBACK_BODY_BYTES,
            expected_content_type="application/json",
            timeout_seconds=FEEDBACK_REQUEST_TIMEOUT_SECONDS,
            timeout_setter=getattr(
                getattr(self, "connection", None),
                "settimeout",
                None,
            ),
        )
        payload = decode_strict_json_body(body)
        if not isinstance(payload, dict):
            raise HTTPBodyError(
                HTTPStatus.BAD_REQUEST,
                "invalid_json_object",
                "request body must contain a JSON object",
            )
        return payload

    def do_POST(self) -> None:
        try:
            self._do_POST()
        except Exception as exc:
            self._handle_unexpected_error("post_failed", exc)

    def _do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/analyst-feedback":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._require_write():
            return
        connection = getattr(self, "connection", None)
        if connection is not None and hasattr(connection, "settimeout"):
            connection.settimeout(FEEDBACK_REQUEST_TIMEOUT_SECONDS)
        try:
            payload = self._read_json_body()
        except HTTPBodyError as exc:
            self._send_json(
                exc.status,
                {"error": exc.public_message, "error_code": exc.code},
            )
            return
        storage = self._storage()
        try:
            feedback_id = storage.record_analyst_feedback(
                normalize_submitted_feedback_payload(
                    payload,
                    source="dashboard_api",
                )
            )
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid feedback payload"})
            return
        self._send_json(
            HTTPStatus.CREATED,
            {
                "feedback_id": feedback_id,
                "status": "recorded",
                "timestamp": utc_now(),
            },
        )

    def do_GET(self) -> None:
        try:
            self._do_GET()
        except Exception as exc:
            self._handle_unexpected_error("get_failed", exc)

    def _do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/health", "/health/live", "/live"}:
            self._send_json(HTTPStatus.OK, {"ok": True, "service": "dashboard_api", "timestamp": utc_now()})
            return
        if parsed.path in {"/health/ready", "/ready"}:
            try:
                ready = bool(self._storage().health_check().get("ok"))
            except Exception:
                ready = False
            self._send_json(
                HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "ok": ready,
                    "service": "dashboard_api",
                    "timestamp": utc_now(),
                },
            )
            return
        if not self._require_read():
            return
        if parsed.path == "/operational/metrics":
            storage = self._storage()
            metrics = storage.operational_metrics()
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": bool(
                        (metrics.get("backend_connectivity") or {}).get("ok")
                    ),
                    "service": "dashboard_api",
                    "request_id": self._request_id(),
                    "metrics": metrics,
                    "timestamp": utc_now(),
                },
            )
            return
        if parsed.path == "/predictions/current":
            query = parse_qs(parsed.query)
            session_id = query.get("session_id", [""])[0].strip()
            if not session_id:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "session_id is required"})
                return
            storage = self._storage()
            # Serve only the isolated, versioned Final next-distinct adapter.
            # The legacy prediction_snapshots row remains available through
            # its historical list endpoint but is never a current-route
            # fallback.
            session_row: Dict[str, Any] = {}
            get_session = getattr(storage, "get_session", None)
            if callable(get_session):
                try:
                    session_row = get_session(session_id) or {}
                except Exception:
                    session_row = {}
            final_poc = build_dashboard_prediction(session_id, session_row)
            guidance_snapshot = {"session_id": session_id, "payload": {}}
            self._send_json(
                HTTPStatus.OK,
                {
                    "item": {
                        "schema_version": final_poc.get("schema_version"),
                        "session_id": session_id,
                        "source": "FINAL_POC",
                        "payload": final_poc,
                    },
                    "current_prediction": final_poc,
                    "prediction_source": "FINAL_POC",
                    "response_guidance": _current_decision_payload(self.config, storage, session_id, guidance_snapshot),
                    "session_id": session_id,
                    "timestamp": utc_now(),
                },
            )
            return
        if parsed.path == "/decisions/current":
            query = parse_qs(parsed.query)
            session_id = query.get("session_id", [""])[0].strip()
            if not session_id:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "session_id is required"})
                return
            storage = self._storage()
            snapshot = storage.get_current_prediction_snapshot(session_id) or {"session_id": session_id, "payload": {}}
            self._send_json(
                HTTPStatus.OK,
                {
                    "response_guidance": _current_decision_payload(self.config, storage, session_id, snapshot),
                    "session_id": session_id,
                    "timestamp": utc_now(),
                },
            )
            return
        if parsed.path == "/feedback-review":
            query = parse_qs(parsed.query)
            try:
                limit = min(max(int(query.get("limit", ["1000"])[0]), 1), 5000)
            except ValueError:
                limit = 1000
            feedback_filter = str(query.get("filter", ["all"])[0] or "all").strip().lower()
            if feedback_filter not in FEEDBACK_FILTERS:
                feedback_filter = "all"
            storage = self._storage()
            rows = storage.list_rows("analyst_feedback", limit=limit)
            filtered_rows = filter_feedback_rows(rows, feedback_filter)[:100]
            self._send_json(
                HTTPStatus.OK,
                {
                    "filter": feedback_filter,
                    "items": [
                        api_row_view("analyst_feedback", row)
                        for row in filtered_rows
                    ],
                    "review": build_feedback_review(rows),
                    "timestamp": utc_now(),
                },
            )
            return
        if parsed.path == "/classification-evaluation":
            query = parse_qs(parsed.query)
            try:
                limit = min(max(int(query.get("limit", ["1000"])[0]), 1), 5000)
            except ValueError:
                limit = 1000
            storage = self._storage()
            self._send_json(
                HTTPStatus.OK,
                {
                    "report": classification_metrics(storage.list_classification_review_labels(limit=limit)),
                    "timestamp": utc_now(),
                },
            )
            return
        if parsed.path == "/external-seed-health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "external_seed_health": _external_seed_health_payload(self.config),
                    "timestamp": utc_now(),
                },
            )
            return
        table = TABLES.get(parsed.path)
        if not table:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        query = parse_qs(parsed.query)
        try:
            limit = min(max(int(query.get("limit", ["100"])[0]), 1), 1000)
        except ValueError:
            limit = 100
        storage = self._storage()
        self._send_json(
            HTTPStatus.OK,
            {
                "items": [
                    api_row_view(table, row)
                    for row in storage.list_rows(table, limit=limit)
                ],
                "limit": limit,
                "table": table,
                "timestamp": utc_now(),
            },
        )

    def _handle_unexpected_error(self, event: str, exc: BaseException) -> None:
        print(
            json.dumps(
                log_payload(
                    {
                        "service": "dashboard_api",
                        "event": event,
                        "exception": exc,
                        "request_id": self._request_id(),
                        "timestamp": utc_now(),
                    }
                ),
                sort_keys=True,
            ),
            flush=True,
        )
        self._send_json(
            HTTPStatus.SERVICE_UNAVAILABLE,
            {
                "error": "service temporarily unavailable",
                "request_id": self._request_id(),
            },
        )

    def log_message(self, fmt: str, *args: Any) -> None:
        del fmt
        status = ""
        if len(args) > 1 and str(args[1]).isdigit():
            status = str(args[1])
        print(
            json.dumps(
                log_payload({
                    "service": "dashboard_api",
                    "client": str(self.client_address[0]) if self.client_address else "",
                    "method": str(getattr(self, "command", "") or ""),
                    "path": sanitize_request_target(str(getattr(self, "path", "") or "")),
                    "status": status,
                    "request_id": self._request_id(),
                    "timestamp": utc_now(),
                }),
                sort_keys=True,
            ),
            flush=True,
        )


def _validate_dashboard_runtime(config: ProductionConfig) -> None:
    read_token = str(getattr(config, "dashboard_read_token", "") or "")
    write_token = str(getattr(config, "dashboard_write_token", "") or "")
    validate_configured_bearer_tokens(
        read_token=read_token,
        write_token=write_token,
        service_name="dashboard_api",
    )
    validate_bind_auth(
        str(config.dashboard_host),
        auth_configured=bool(read_token),
        service_name="dashboard_api",
    )


def build_server(
    config: ProductionConfig,
    *,
    storage: Any = None,
) -> BoundedThreadingHTTPServer:
    _validate_dashboard_runtime(config)
    DashboardHandler.config = config
    server = BoundedThreadingHTTPServer(
        (config.dashboard_host, config.dashboard_port),
        DashboardHandler,
        request_timeout_seconds=FEEDBACK_REQUEST_TIMEOUT_SECONDS,
    )
    if storage is not None:
        server.storage = storage
    return server


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the read-only dashboard API.")
    parser.add_argument("--config", help="Path to production JSON config.")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    _validate_dashboard_runtime(config)
    storage = open_storage(config.database_settings())
    server = build_server(config, storage=storage)
    print(
        json.dumps(
            {
                "service": "dashboard_api",
                "host": config.dashboard_host,
                "port": config.dashboard_port,
                "database": config.safe_database_descriptor(),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    serve_http_until_stopped(server)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
