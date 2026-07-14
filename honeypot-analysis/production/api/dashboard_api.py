"""Dashboard API for operator visibility and analyst feedback."""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from production.utils.config import ProductionConfig
from production.prediction.external_seed_health import infer_external_seed_paths, load_external_seed_health
from production.classification.classification_evaluation import classification_metrics
from production.tools.feedback_review import FEEDBACK_FILTERS, build_feedback_review, filter_feedback_rows
from production.utils.serialization import utc_now
from production.reporting.smb_decision import build_smb_decision_from_paths
from production.storage import open_storage


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
        "session_id": payload.get("session_id") or snapshot.get("session_id"),
        "generated_at": payload.get("generated_at") or snapshot.get("created_at"),
        "final_ranking": final_ranking,
        "prediction": payload.get("prediction") or [],
        "source_breakdown": source_breakdown,
        "local_transition_model": payload.get("local_transition_model") or payload.get("model_maturity") or {},
        "external_seed_model": payload.get("external_seed_model") or {},
        "classification_quality": payload.get("classification_quality") or {},
        "session_ttp_correlations": (payload.get("features") or {}).get("session_ttp_correlations") or [],
        "session_ttp_correlation_summary": (payload.get("features") or {}).get("session_ttp_correlation_summary") or {},
        "session_evidence_graph_summary": (payload.get("features") or {}).get("session_evidence_graph_summary") or {},
        "calibration_status": payload.get("calibration_status") or {},
        "weight_calibration": payload.get("weight_calibration") or {},
        "trust_status": payload.get("trust_status") or {},
        "agreement": payload.get("agreement") or {},
        "coverage": payload.get("coverage") or {},
        "confidence_damping": payload.get("confidence_damping") or {},
        "prediction_trigger": payload.get("prediction_trigger") or {},
        "predictive_alert": payload.get("predictive_alert") or {},
        "effective_weights": payload.get("effective_weights") or {},
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
    for row in storage.list_rows("sessions", limit=5000):
        if str(row.get("session_id") or "") == session_id:
            payload = _payload_from_row(row)
            payload.setdefault("session_id", session_id)
            payload.setdefault("src_ip", row.get("src_ip") or "unknown")
            return payload
    return {"session_id": session_id}


def _current_decision_payload(config: ProductionConfig, storage: Any, session_id: str, snapshot: Dict[str, Any]) -> Dict[str, Any]:
    if not config.enable_smb_decisions:
        return {"enabled": False, "reason": "SMB decision layer disabled"}
    return build_smb_decision_from_paths(
        session_payload=_session_payload_for_id(storage, session_id),
        prediction_snapshot=snapshot,
        asset_profile_path=config.smb_asset_profile_path,
        action_policy_path=config.smb_action_policy_path,
        mitre_attack_path=config.mitre_attack_path,
    )


def _external_seed_health_payload(config: ProductionConfig) -> Dict[str, Any]:
    paths = infer_external_seed_paths(config.prediction_policy)
    return load_external_seed_health(
        paths["health"],
        model_path=paths["model"],
        validation_path=paths["validation"],
        review_path=paths["review"],
        include_review=False,
    )


class DashboardHandler(BaseHTTPRequestHandler):
    config: ProductionConfig

    def _send_json(self, status: HTTPStatus, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        body = self.rfile.read(min(length, 1_000_000))
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/analyst-feedback":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        payload = self._read_json_body()
        storage = open_storage(self.config.database_url)
        try:
            feedback_id = storage.record_analyst_feedback(payload)
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
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
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(HTTPStatus.OK, {"ok": True, "service": "dashboard_api", "timestamp": utc_now()})
            return
        if parsed.path == "/predictions/current":
            query = parse_qs(parsed.query)
            session_id = query.get("session_id", [""])[0].strip()
            if not session_id:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "session_id is required"})
                return
            storage = open_storage(self.config.database_url)
            snapshot = storage.get_latest_prediction_snapshot(session_id)
            if not snapshot:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": "prediction not found", "session_id": session_id, "timestamp": utc_now()},
                )
                return
            feedback_rows = [
                row
                for row in storage.list_rows("analyst_feedback", limit=1000)
                if str(row.get("session_id") or "") == session_id
            ]
            self._send_json(
                HTTPStatus.OK,
                {
                    "item": snapshot,
                    "current_prediction": _current_prediction_payload(snapshot, feedback_rows),
                    "smb_decision": _current_decision_payload(self.config, storage, session_id, snapshot),
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
            storage = open_storage(self.config.database_url)
            snapshot = storage.get_latest_prediction_snapshot(session_id) or {"session_id": session_id, "payload": {}}
            self._send_json(
                HTTPStatus.OK,
                {
                    "smb_decision": _current_decision_payload(self.config, storage, session_id, snapshot),
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
            storage = open_storage(self.config.database_url)
            rows = storage.list_rows("analyst_feedback", limit=limit)
            self._send_json(
                HTTPStatus.OK,
                {
                    "filter": feedback_filter,
                    "items": filter_feedback_rows(rows, feedback_filter)[:100],
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
            storage = open_storage(self.config.database_url)
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
        storage = open_storage(self.config.database_url)
        self._send_json(
            HTTPStatus.OK,
            {
                "items": storage.list_rows(table, limit=limit),
                "limit": limit,
                "table": table,
                "timestamp": utc_now(),
            },
        )

    def log_message(self, fmt: str, *args: Any) -> None:
        print(
            json.dumps(
                {
                    "service": "dashboard_api",
                    "client": self.address_string(),
                    "message": fmt % args,
                    "timestamp": utc_now(),
                },
                sort_keys=True,
            ),
            flush=True,
        )


def build_server(config: ProductionConfig) -> ThreadingHTTPServer:
    DashboardHandler.config = config
    return ThreadingHTTPServer((config.dashboard_host, config.dashboard_port), DashboardHandler)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the read-only dashboard API.")
    parser.add_argument("--config", help="Path to production JSON config.")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    storage = open_storage(config.database_url)
    storage.initialize()
    server = build_server(config)
    print(
        json.dumps(
            {
                "service": "dashboard_api",
                "host": config.dashboard_host,
                "port": config.dashboard_port,
                "database_url": config.database_url,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
