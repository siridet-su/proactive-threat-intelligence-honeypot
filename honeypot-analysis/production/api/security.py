"""Shared access decisions and redacted API view models."""

from __future__ import annotations

import json
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Dict, Iterable, Mapping

from production.utils.http_security import (
    constant_time_token_match,
    parse_bearer_token,
)
from production.utils.sensitive_data import (
    redact_for_api,
    redact_for_log,
    sanitize_url,
)


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    status: HTTPStatus = HTTPStatus.OK
    error: str = ""


def validate_configured_bearer_tokens(
    *,
    read_token: str,
    write_token: str,
    service_name: str,
) -> None:
    """Reject configured credentials that strict Bearer parsing cannot present."""
    for field_name, configured in (
        ("read token", str(read_token or "")),
        ("write token", str(write_token or "")),
    ):
        if not configured:
            continue
        if parse_bearer_token(f"Bearer {configured}") != configured:
            raise ValueError(
                f"{service_name} {field_name} is not a valid Bearer token value"
            )


def authorize_read(
    authorization_header: str | None,
    expected_token: str,
    *,
    allow_anonymous: bool,
) -> AccessDecision:
    """Authorize a read without silently enabling a network-facing service."""
    token = str(expected_token or "")
    if not token:
        if allow_anonymous:
            return AccessDecision(True)
        return AccessDecision(
            False,
            HTTPStatus.SERVICE_UNAVAILABLE,
            "read authentication is not configured",
        )
    candidate = parse_bearer_token(authorization_header)
    if constant_time_token_match(candidate, token):
        return AccessDecision(True)
    return AccessDecision(
        False,
        HTTPStatus.UNAUTHORIZED,
        "Bearer authentication required",
    )


def authorize_write(
    authorization_header: str | None,
    read_token: str,
    write_token: str,
) -> AccessDecision:
    """Require an explicit write credential, falling back to a configured read token."""
    configured_read = str(read_token or "")
    configured_write = str(write_token or "")
    if not configured_write and not configured_read:
        return AccessDecision(
            False,
            HTTPStatus.SERVICE_UNAVAILABLE,
            "write authentication is not configured",
        )

    candidate = parse_bearer_token(authorization_header)
    read_match = constant_time_token_match(candidate, configured_read)
    write_match = constant_time_token_match(candidate, configured_write)
    if configured_write and write_match:
        return AccessDecision(True)
    if not configured_write and read_match:
        return AccessDecision(True)
    if configured_write and read_match:
        return AccessDecision(
            False,
            HTTPStatus.FORBIDDEN,
            "write scope required",
        )
    return AccessDecision(
        False,
        HTTPStatus.UNAUTHORIZED,
        "Bearer authentication required",
    )


def public_payload(value: Any) -> Any:
    """Delegate recursive JSON-safe redaction to the central sensitive-data policy."""
    return redact_for_api(value)


def log_payload(value: Any) -> Any:
    """Delegate structured-log redaction to the central sensitive-data policy."""
    return redact_for_log(value)


def _row_payload(row: Mapping[str, Any]) -> Dict[str, Any]:
    payload = row.get("payload")
    if isinstance(payload, Mapping):
        return dict(payload)
    try:
        loaded = json.loads(str(row.get("payload_json") or "{}"))
    except (TypeError, ValueError):
        loaded = {}
    return loaded if isinstance(loaded, dict) else {}


def _pick(source: Mapping[str, Any], names: Iterable[str]) -> Dict[str, Any]:
    return {
        name: source.get(name)
        for name in names
        if source.get(name) not in (None, "")
    }


COMMON_ROW_FIELDS = (
    "event_id",
    "session_id",
    "alert_id",
    "job_id",
    "report_id",
    "snapshot_id",
    "run_id",
    "feedback_id",
    "label_id",
    "review_id",
    "sighting_id",
    "link_id",
    "campaign_id",
    "delivery_id",
    "name",
    "status",
    "severity",
    "created_at",
    "updated_at",
)


def api_row_view(table: str, row: Mapping[str, Any]) -> Dict[str, Any]:
    """Project one storage row into a deliberately bounded public representation."""
    item = dict(row)
    payload = _row_payload(item)
    view = _pick(item, COMMON_ROW_FIELDS)

    if table == "events":
        view.update(
            _pick(
                item,
                (
                    "sensor_id",
                    "src_ip",
                    "eventid",
                    "timestamp",
                    "received_at",
                    "processed",
                ),
            )
        )
    elif table == "sessions":
        view.update(
            _pick(
                item,
                (
                    "src_ip",
                    "start_time",
                    "ended",
                    "session_source",
                    "is_external_source",
                ),
            )
        )
        view.update(
            {
                "sensor_id": payload.get("sensor_id") or payload.get("sensor") or "",
                "command_count": len(payload.get("commands") or []),
                "tactics": payload.get("tactics") or [],
                "ttps": payload.get("ttps") or [],
                "analysis_status": payload.get("analysis_status") or payload.get("status") or "",
            }
        )
    elif table == "alerts":
        view.update(_pick(item, ("reason", "delivered")))
    elif table in {"analysis_jobs", "enrichment_jobs", "threat_hunt_jobs"}:
        view.update(
            _pick(
                item,
                (
                    "observable_type",
                    "observable_value",
                    "priority",
                    "attempts",
                    "next_retry_at",
                    "report_id",
                    "error",
                ),
            )
        )
    elif table == "reports":
        view["summary"] = payload.get("summary") or payload.get("executive_summary") or ""
        view["confidence"] = payload.get("confidence") or ""
    elif table == "prediction_snapshots":
        view.update(_pick(item, ("src_ip", "session_status", "event_id", "features_hash")))
        view.update(
            {
                "generated_at": payload.get("generated_at") or item.get("created_at"),
                "prediction": payload.get("prediction") or [],
                "final_ranking": payload.get("final_ranking") or [],
                "trust_status": payload.get("trust_status") or {},
                "coverage": payload.get("coverage") or {},
            }
        )
    elif table in {"prediction_backtest_runs", "prediction_calibration_runs"}:
        view.update(
            {
                "generated_at": payload.get("generated_at") or item.get("created_at"),
                "metrics": payload.get("metrics") or {},
                "applied": payload.get("applied") or payload.get("apply") or False,
            }
        )
    elif table == "analyst_feedback":
        view.update(
            _pick(
                item,
                (
                    "snapshot_id",
                    "label",
                    "feedback_type",
                    "operator_signal",
                    "action_status",
                    "evidence_origin",
                    "weight_eligible",
                    "correct_next_tactic",
                    "predicted_top_tactic",
                    "final_actual_next_tactic",
                    "tactic_granularity",
                ),
            )
        )
    elif table == "classification_review_labels":
        view.update(
            _pick(
                item,
                (
                    "command_index",
                    "predicted_ttp",
                    "predicted_tactic",
                    "predicted_source",
                    "predicted_confidence",
                    "reviewed_ttp",
                    "reviewed_tactic",
                ),
            )
        )
    elif table in {"enrichment_records", "observables"}:
        view.update(
            _pick(
                item,
                (
                    "observable_type",
                    "observable_value",
                    "first_seen",
                    "last_seen",
                    "expires_at",
                    "sighting_count",
                    "is_stale",
                ),
            )
        )
        provider_status = item.get("provider_status")
        if not isinstance(provider_status, Mapping):
            try:
                provider_status = json.loads(str(item.get("provider_status_json") or "{}"))
            except (TypeError, ValueError):
                provider_status = {}
        view["provider_status"] = provider_status if isinstance(provider_status, Mapping) else {}
    elif table == "observable_sightings":
        view.update(
            _pick(
                item,
                (
                    "observable_type",
                    "observable_value",
                    "sensor_id",
                    "src_ip",
                    "event_id",
                    "eventid",
                    "role",
                    "source",
                    "timestamp",
                ),
            )
        )
    elif table == "session_links":
        view.update(
            _pick(
                item,
                (
                    "session_id_a",
                    "session_id_b",
                    "link_type",
                    "observable_type",
                    "observable_value",
                    "confidence",
                ),
            )
        )
    elif table == "campaigns":
        view.update(
            _pick(
                item,
                (
                    "primary_fingerprint_type",
                    "source_ip",
                    "session_count",
                    "first_seen",
                    "last_seen",
                    "max_confirmed_severity",
                ),
            )
        )
        view["confirmed_tactics"] = item.get("confirmed_tactics") or []
    elif table == "campaign_sessions":
        view.update(_pick(item, ("campaign_id", "session_id", "confidence")))
        view["match_reasons"] = item.get("match_reasons") or []
    elif table == "feed_status":
        view.update(
            {
                "feed_status": payload.get("status") or payload.get("state") or "",
                "last_success": payload.get("last_success") or payload.get("updated_at") or "",
                "stale": payload.get("stale"),
            }
        )
    elif table == "webhook_deliveries":
        view.update(
            _pick(
                item,
                (
                    "alert_id",
                    "report_id",
                    "target_url_hash",
                    "attempts",
                    "last_error",
                ),
            )
        )

    return public_payload(view)


def event_views(rows: Iterable[Mapping[str, Any]]) -> list[Dict[str, Any]]:
    output = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        normalized = dict(row)
        normalized.setdefault("session_id", row.get("session"))
        normalized.setdefault("sensor_id", row.get("sensor"))
        output.append(api_row_view("events", normalized))
    return output


def session_detail_view(detail: Mapping[str, Any]) -> Dict[str, Any]:
    """Return useful session analysis without raw events or storage documents."""
    if not detail.get("ok"):
        return public_payload(dict(detail))
    session_payload = detail.get("session_payload")
    if not isinstance(session_payload, Mapping):
        session_payload = {}
    output: Dict[str, Any] = {
        "ok": True,
        "timestamp": detail.get("timestamp"),
        "session_id": detail.get("session_id"),
        "overview": detail.get("overview") or {},
        "source_geo": detail.get("source_geo") or {},
        "source_geo_context": detail.get("source_geo_context") or {},
        "observables": detail.get("observables") or [],
        "likely_next_steps": detail.get("likely_next_steps") or [],
        "commands": detail.get("commands") or [],
        "classification_events": detail.get("classification_events") or [],
        "session_ttp_correlations": detail.get("session_ttp_correlations") or [],
        "session_ttp_correlation_summary": detail.get("session_ttp_correlation_summary") or {},
        "tactics": detail.get("tactics") or [],
        "ttps": detail.get("ttps") or [],
        "ttp_command_map": detail.get("ttp_command_map") or {},
        "enrichment_status": detail.get("enrichment_status") or {},
        "session": {
            "session_id": session_payload.get("session_id"),
            "sensor_id": session_payload.get("sensor_id") or session_payload.get("sensor"),
            "src_ip": session_payload.get("src_ip"),
            "start_time": session_payload.get("start_time"),
            "duration": session_payload.get("duration"),
            "is_ended": session_payload.get("is_ended"),
            "command_count": len(session_payload.get("commands") or []),
            "analysis_status": session_payload.get("analysis_status") or session_payload.get("status"),
        },
        "events": event_views(detail.get("events_table_rows") or []),
        "alerts": [
            api_row_view("alerts", row) for row in detail.get("alerts") or []
        ],
        "prediction_snapshots": [
            api_row_view("prediction_snapshots", row)
            for row in detail.get("prediction_snapshots") or []
        ],
        "analyst_feedback": [
            api_row_view("analyst_feedback", row)
            for row in detail.get("analyst_feedback") or []
        ],
        "observable_sightings": [
            api_row_view("observable_sightings", row)
            for row in detail.get("observable_sightings") or []
        ],
        "related_observable_sightings": [
            api_row_view("observable_sightings", row)
            for row in detail.get("related_observable_sightings") or []
        ],
        "session_links": [
            api_row_view("session_links", row)
            for row in detail.get("session_links") or []
        ],
        "threat_hunt_jobs": [
            api_row_view("threat_hunt_jobs", row)
            for row in detail.get("threat_hunt_jobs") or []
        ],
        "campaigns": [
            api_row_view("campaigns", row)
            for row in detail.get("campaigns") or []
        ],
        "enrichment_records": [
            api_row_view("enrichment_records", row)
            for row in detail.get("enrichment_records") or []
        ],
        "enrichment_jobs": [
            api_row_view("enrichment_jobs", row)
            for row in detail.get("enrichment_jobs") or []
        ],
        "analysis_jobs": [
            api_row_view("analysis_jobs", row)
            for row in detail.get("analysis_jobs") or []
        ],
        "reports": [
            api_row_view("reports", row) for row in detail.get("reports") or []
        ],
        "report_summary": detail.get("report_summary") or {},
        "report_recommendations": detail.get("report_recommendations") or [],
        "response_guidance": detail.get("response_guidance") or {},
        "errors": detail.get("errors") or {},
    }
    return public_payload(output)


def sanitize_request_target(target: str) -> str:
    """Redact sensitive query values from a request target before logging."""
    return sanitize_url(str(target or ""))[:2048]
