"""Shared access decisions and redacted API view models."""

from __future__ import annotations

import json
import posixpath
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
from production.correlation.semantics import (
    resolve_confidence_semantics,
)
from production.correlation.session_ttp_knowledge import TTP_ID_RE, main_ttp_id


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    status: HTTPStatus = HTTPStatus.OK
    error: str = ""


def validate_configured_bearer_tokens(
    *,
    read_token: str,
    write_token: str,
    admin_token: str = "",
    service_name: str,
) -> None:
    """Reject configured credentials that strict Bearer parsing cannot present."""
    for field_name, configured in (
        ("read token", str(read_token or "")),
        ("write token", str(write_token or "")),
        ("admin token", str(admin_token or "")),
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


def _safe_cwd_path(value: Any) -> str:
    """Return only an absolute, bounded working-directory path.

    Cowrie's ``cowrie.session.cwd`` event is useful filesystem telemetry, but
    the event payload may also contain command-shaped fields.  Project the
    path as a dedicated derived field instead of forwarding that payload.
    """

    if not isinstance(value, str):
        return ""
    candidate = value.strip()
    if not candidate or len(candidate) > 2_048 or "\x00" in candidate:
        return ""
    if not candidate.startswith("/"):
        return ""
    normalized = posixpath.normpath(candidate)
    if not normalized.startswith("/") or normalized == ".":
        return ""
    return normalized


def _cwd_event_fields(row: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Project safe CWD metadata from one canonical Cowrie event row."""

    eventid = str(row.get("eventid") or payload.get("eventid") or "").strip().lower()
    if eventid != "cowrie.session.cwd":
        return {}
    to_path = _safe_cwd_path(
        row.get("cwd_path")
        or payload.get("cwd_path")
        or payload.get("cwd")
        or payload.get("cwd_after")
        or payload.get("to_cwd")
        or payload.get("to_path")
        or payload.get("path")
    )
    from_path = _safe_cwd_path(
        row.get("cwd_from_path")
        or payload.get("cwd_from_path")
        or payload.get("oldcwd")
        or payload.get("cwd_before")
        or payload.get("from_cwd")
        or payload.get("from_path")
        or payload.get("previous_cwd")
    )
    if not to_path:
        return {}
    return {
        "cwd_path": to_path,
        **({"cwd_from_path": from_path} if from_path else {}),
        "cwd_action": "changed" if from_path and from_path != to_path else "entered",
        "cwd_status": "observed",
    }


def _is_command_event_row(row: Mapping[str, Any]) -> bool:
    """Identify Cowrie command-input rows before privacy projection."""
    payload = _row_payload(row)
    event_id = row.get("eventid") or payload.get("eventid")
    normalized_event_id = str(event_id or "").strip().lower()
    return normalized_event_id == "cowrie.command.input" or (
        normalized_event_id.startswith("cowrie.")
        and normalized_event_id.endswith(".input")
        and "[redacted]" in normalized_event_id
        and bool(str(payload.get("input") or "").strip())
    )


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
                    "command_event",
                ),
            )
        )
        view.update(_cwd_event_fields(item, payload))
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
        view["authority_display"] = "historical_legacy_alert"
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
                "evidence_cutoff": payload.get("evidence_cutoff") or {},
            }
        )
        # Next Distinct is a read-only advisory sidecar, not a canonical
        # prediction snapshot. Preserve its bounded provenance fields when
        # it is projected into the session-detail read model so the detail
        # endpoint and /api/next-distinct expose the same source semantics.
        for field in (
            "prediction_type",
            "prediction_status",
            "prediction_status_reason",
            "source",
            "prediction_source",
            "dashboard_source",
            "state",
            "status",
            "availability",
            "authority",
            "advisory_only",
            "read_only",
            "canonical_write_allowed",
            "next_distinct_tactic",
            "stored_next_distinct_tactic",
            "top1",
            "top3",
            "probabilities",
            "freshness",
            "history",
            "model",
            "sequence_id",
            "progression_index",
            "sidecar_record_schema",
            "snapshot_role",
            "historical_advisory",
        ):
            if field in payload:
                view[field] = payload[field]
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
        view["confidence_semantics"] = resolve_confidence_semantics(
            item.get("confidence_semantics") or payload.get("confidence_semantics")
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
        view["confidence_semantics"] = resolve_confidence_semantics(
            item.get("confidence_semantics") or payload.get("confidence_semantics")
        )
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
        # Expose only event-type metadata; command text stays redacted.
        normalized["command_event"] = _is_command_event_row(row)
        output.append(api_row_view("events", normalized))
    return output


def count_command_events(rows: Iterable[Mapping[str, Any]]) -> int:
    """Count command-input events without relying on denormalized payloads.

    Session payloads can legitimately omit ``commands`` when the durable event
    rows are the only source of command evidence. Keep the monitor count tied
    to the Cowrie event shape rather than treating arbitrary event names or
    stored command lists as commands. Some historical records were persisted
    after a privacy boundary redacted the middle of ``cowrie.command.input``.
    Those records retain the ``*.input`` event shape and a non-empty ``input``
    field, so they remain countable without restoring or exposing command text.
    """

    count = 0
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        if not _is_command_event_row(row):
            continue
        payload = _row_payload(row)
        # Cowrie can emit an input event for an empty submitted line.  Such a
        # row is useful terminal telemetry, but it is not a command and is
        # omitted by both the private command projection and report builder.
        # Keep historical rows countable when their payload did not retain an
        # input key; only exclude an explicitly recorded blank input.
        if "input" in payload and not str(payload.get("input") or "").strip():
            continue
        count += 1
    return count


_PUBLIC_COMMAND_TEXT_KEYS = frozenset(
    {
        "command",
        "commands",
        "input",
        "raw_command",
        "command_text",
        "command_line",
        "ttp_command_map",
        "command_map",
    }
)


def _redact_public_command_text(value: Any, key: str = "") -> Any:
    """Keep public command-shaped fields bounded without exposing input text."""
    if key in _PUBLIC_COMMAND_TEXT_KEYS:
        if isinstance(value, list):
            return ["[REDACTED]" for _ in value]
        if isinstance(value, tuple):
            return ["[REDACTED]" for _ in value]
        if isinstance(value, Mapping):
            return {
                str(name): _redact_public_command_text(item, "commands")
                for name, item in value.items()
            }
        return "[REDACTED]" if value not in (None, "") else value
    if isinstance(value, Mapping):
        return {
            str(name): _redact_public_command_text(item, str(name))
            for name, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_public_command_text(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_public_command_text(item) for item in value]
    return value


_COMPACT_SESSION_DETAIL_EVENT_LIMIT = 100
_COMPACT_SESSION_DETAIL_TRUSTED_LIMIT = 50
_COMPACT_SESSION_DETAIL_CORRELATION_LIMIT = 20
_COMPACT_SESSION_DETAIL_CLASSIFICATION_LIMIT = 100
_COMPACT_SESSION_DETAIL_TACTIC_PATH_LIMIT = 50
_COMPACT_SESSION_DETAIL_TEXT_LIMIT = 160
_COMPACT_SESSION_DETAIL_GUIDANCE_LIMIT = 20
_COMPACT_SESSION_DETAIL_GUIDANCE_LIST_LIMIT = 8


def _compact_scalar_fields(source: Mapping[str, Any], names: Iterable[str]) -> Dict[str, Any]:
    """Pick bounded scalar metadata without forwarding free-form evidence text."""
    projected: Dict[str, Any] = {}
    for name in names:
        value = source.get(name)
        if isinstance(value, str) and value:
            projected[name] = value[:_COMPACT_SESSION_DETAIL_TEXT_LIMIT]
        elif isinstance(value, bool):
            projected[name] = value
        elif isinstance(value, int):
            projected[name] = value
        elif isinstance(value, float) and value == value and abs(value) != float("inf"):
            projected[name] = value
    return projected


def _compact_classification_traceability(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    projected = _compact_scalar_fields(
        value,
        (
            "event_id",
            "policy_or_rule_identifier",
            "model_source",
            "authority_state",
            "evidence_tier",
        ),
    )
    source_event = value.get("source_event")
    if isinstance(source_event, Mapping):
        safe_source_event = _compact_scalar_fields(
            source_event,
            ("cowrie_eventid", "event_type", "event_id"),
        )
        if safe_source_event:
            projected["source_event"] = safe_source_event
    for field, count_field in (
        ("evidence_references", "evidence_reference_count"),
        ("source_event_ids", "source_event_count"),
    ):
        values = value.get(field)
        if isinstance(values, list):
            projected[count_field] = len(values)
    return projected


def _compact_classification_events(items: Any) -> list[Dict[str, Any]]:
    """Project classifier provenance while excluding command/source text."""
    output: list[Dict[str, Any]] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, Mapping):
            continue
        item = _normalize_inactive_classifier_event_for_public(item)
        projected = _compact_scalar_fields(
            item,
            (
                "evidence_id",
                "event_id",
                "command_event_id",
                "event_timestamp",
                "timestamp",
                "eventid",
                "cowrie_eventid",
                "ttp",
                "technique_id",
                "name",
                "tactic",
                "evidence_tier",
                "evidence_type",
                "authority",
                "source",
                "rule_id",
                "confidence_semantics",
            ),
        )
        for field in ("ttp", "technique_id"):
            identifier = projected.get(field)
            if isinstance(identifier, str) and TTP_ID_RE.fullmatch(identifier.strip()):
                projected[field] = main_ttp_id(identifier)
        tactics = item.get("tactics")
        if isinstance(tactics, list):
            projected["tactics"] = [
                value[:80]
                for value in tactics[:20]
                if isinstance(value, str) and value
            ]
        for source_key, safe_fields in (
            ("authority_decision", ("decision", "authority", "evidence_tier", "status")),
            ("s1_advisory", ("predicted_technique", "decision_score", "confidence_semantics")),
            ("durable_evidence_order", ("event_id", "event_index")),
        ):
            nested = item.get(source_key)
            if isinstance(nested, Mapping):
                safe_nested = _compact_scalar_fields(nested, safe_fields)
                if safe_nested:
                    projected[source_key] = safe_nested
        traceability = _compact_classification_traceability(item.get("traceability"))
        if traceability:
            projected["traceability"] = traceability
        output.append(projected)
        if len(output) >= _COMPACT_SESSION_DETAIL_CLASSIFICATION_LIMIT:
            break
    return output


def _normalize_inactive_classifier_event_for_public(
    item: Mapping[str, Any],
) -> Dict[str, Any]:
    """Hide the historical disabled-model marker without rewriting storage."""

    normalized = dict(item)
    if str(normalized.get("source") or "").strip().lower() != "securebert_unavailable":
        return normalized
    normalized.update(
        {
            "source": "unclassified",
            "name": "No active classifier",
            "evidence_type": "unclassified",
            "agreement_status": "not_applicable",
            "confidence_semantics": "no_active_model_or_reviewed_rule",
        }
    )
    for field in ("bert_ttp", "bert_tactic", "bert_confidence", "model_inference"):
        normalized.pop(field, None)
    authority = normalized.get("authority_decision")
    if isinstance(authority, Mapping):
        normalized["authority_decision"] = {
            **dict(authority),
            "decision": "audit_only",
            "trusted_eligible": False,
            "reasons": ["no_active_model_or_reviewed_rule"],
        }
    return normalized


def _compact_observed_tactic_path(items: Any) -> list[Dict[str, Any]]:
    """Keep only ordered tactic labels and bounded counts, never command text."""
    output: list[Dict[str, Any]] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, Mapping):
            continue
        tactic = item.get("tactic")
        if not isinstance(tactic, str) or not tactic.strip():
            continue
        projected = {"tactic": tactic.strip()[:80]}
        for source_field, count_field in (
            ("techniques", "technique_count"),
            ("evidence_refs", "evidence_ref_count"),
            ("event_ids", "event_count"),
        ):
            values = item.get(source_field)
            if isinstance(values, list):
                projected[count_field] = len(values)
        output.append(projected)
        if len(output) >= _COMPACT_SESSION_DETAIL_TACTIC_PATH_LIMIT:
            break
    return output


def _bounded_guidance_text_list(value: Any) -> list[str]:
    """Keep policy-authored guidance text bounded and free of raw evidence."""

    output: list[str] = []
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, str):
            continue
        text = item.strip()
        if not text:
            continue
        output.append(text[:_COMPACT_SESSION_DETAIL_TEXT_LIMIT])
        if len(output) >= _COMPACT_SESSION_DETAIL_GUIDANCE_LIST_LIMIT:
            break
    return output


def _compact_guidance_records(items: Any, *, kind: str) -> list[Dict[str, Any]]:
    """Expose useful policy guidance without forwarding evidence or commands."""

    output: list[Dict[str, Any]] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, Mapping):
            continue
        if kind == "finding":
            projected = _compact_scalar_fields(
                item,
                (
                    "finding_id",
                    "finding_type",
                    "severity",
                    "statement",
                    "rule_id",
                    "evidence_status",
                    "authority",
                ),
            )
        else:
            projected = _compact_scalar_fields(
                item,
                (
                    "action_id",
                    "description",
                    "rationale",
                    "rule_id",
                    "priority",
                ),
            )
            for field in (
                "requires_manual_approval",
                "safe_to_auto_execute",
            ):
                value = item.get(field)
                if isinstance(value, bool):
                    projected[field] = value
            for field in ("preconditions", "verification_steps"):
                values = _bounded_guidance_text_list(item.get(field))
                if values:
                    projected[field] = values
        if projected:
            output.append(projected)
        if len(output) >= _COMPACT_SESSION_DETAIL_GUIDANCE_LIMIT:
            break
    return output


def _compact_session_guidance(guidance: Any) -> Dict[str, Any]:
    """Project safety plus bounded policy content without shipping evidence."""

    source = dict(guidance) if isinstance(guidance, Mapping) else {}
    safety = source.get("safety") if isinstance(source.get("safety"), Mapping) else {}
    binding = source.get("binding") if isinstance(source.get("binding"), Mapping) else {}
    assessment = binding.get("assessment") if isinstance(binding.get("assessment"), Mapping) else {}
    validation = source.get("validation") if isinstance(source.get("validation"), Mapping) else {}
    presentation = (
        source.get("presentation_semantics")
        if isinstance(source.get("presentation_semantics"), Mapping)
        else {}
    )
    manual = source.get("requires_manual_approval")
    if not isinstance(manual, bool):
        manual = safety.get("manual_approval_required")
    manual = manual if isinstance(manual, bool) else True
    auto_execute = source.get("safe_to_auto_execute")
    if not isinstance(auto_execute, bool):
        auto_execute = safety.get("automatic_execution")
    auto_execute = bool(auto_execute) if not manual and isinstance(auto_execute, bool) else False
    result = {
        "schema_version": source.get("schema_version") or "response_guidance.v3",
        "guidance_id": source.get("guidance_id") or "",
        "status": source.get("status") or "unavailable",
        "guidance_state": source.get("guidance_state") or "stored_guidance_unverified",
        "authority": source.get("authority") or "policy_unavailable",
        "session_id": source.get("session_id") or "",
        "requires_manual_approval": manual,
        "safe_to_auto_execute": auto_execute,
        "safety": {
            "automatic_execution": False,
            "manual_approval_required": manual,
            "alerting_side_effect": bool(safety.get("alerting_side_effect", False)),
            "response_action_side_effect": bool(safety.get("response_action_side_effect", False)),
            "execution_integration": safety.get("execution_integration") or "not_implemented",
        },
        "binding": {
            "schema_version": binding.get("schema_version") or "response_guidance_binding.v1",
            "status": binding.get("status") or "unverified",
            "session_id": binding.get("session_id") or source.get("session_id") or "",
            "assessment": {
                "status": assessment.get("status") or "unverified",
                "assessment_id": assessment.get("assessment_id") or "",
            },
        },
        "validation": {
            "status": validation.get("status") or "unverified",
            "error_count": len(validation.get("errors") or []) if isinstance(validation.get("errors"), list) else 0,
        },
        "presentation_semantics": {
            "mode": presentation.get("mode") or "stored_guidance_unverified",
            "historical_record": bool(presentation.get("historical_record", False)),
            "stored_report": bool(presentation.get("stored_report", False)),
            "recomputed": bool(presentation.get("recomputed", False)),
        },
        "finding_count": len(source.get("findings") or []) if isinstance(source.get("findings"), list) else 0,
        "advisory_action_count": len(source.get("advisory_actions") or []) if isinstance(source.get("advisory_actions"), list) else 0,
        "findings": _compact_guidance_records(source.get("findings"), kind="finding"),
        "advisory_actions": _compact_guidance_records(source.get("advisory_actions"), kind="action"),
    }
    return public_payload(result)


def _compact_trusted_observations(items: Any) -> list[Dict[str, Any]]:
    output: list[Dict[str, Any]] = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, str):
            identifier = item.strip().upper()
            if TTP_ID_RE.fullmatch(identifier):
                parent_identifier = main_ttp_id(identifier)
                if parent_identifier != "T0000":
                    output.append(
                        {
                            "technique_id": parent_identifier,
                            "trust_tier": "trusted_observation",
                            "mapping_semantics": "stored trusted identifier; supporting metadata unavailable",
                        }
                    )
            if len(output) >= _COMPACT_SESSION_DETAIL_TRUSTED_LIMIT:
                break
            continue
        if not isinstance(item, Mapping):
            continue
        projected = _pick(
            item,
            (
                "technique_id",
                "ttp",
                "tactic",
                "tactics",
                "trust_tier",
                "authority",
                "confidence",
                "confidence_semantics",
                "mapping_scope",
                "mapping_semantics",
                "observation_namespace",
                "evidence_tier",
            ),
        )
        identifier = item.get("technique_id") or item.get("ttp")
        if isinstance(identifier, str) and TTP_ID_RE.fullmatch(identifier.strip()):
            parent_identifier = main_ttp_id(identifier)
            if parent_identifier != "T0000":
                projected["technique_id"] = parent_identifier
            else:
                projected.pop("technique_id", None)
                projected.pop("ttp", None)
        if isinstance(item.get("commands"), list):
            projected["command_count"] = len(item["commands"])
        if isinstance(item.get("evidence_refs"), list):
            projected["evidence_ref_count"] = len(item["evidence_refs"])
        output.append(projected)
        if len(output) >= _COMPACT_SESSION_DETAIL_TRUSTED_LIMIT:
            break
    return output


def _compact_correlations(items: Any) -> list[Dict[str, Any]]:
    output: list[Dict[str, Any]] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, Mapping):
            continue
        projected = _pick(
            item,
            (
                "correlation_id",
                "ttp",
                "source_ttp",
                "technique_name",
                "tactic",
                "strength",
                "confidence",
                "strength_semantics",
                "confidence_semantics",
                "claim_status",
                "authority",
                "prediction_eligibility",
                "evidence_type",
                "correlation_kind",
                "influence_scope",
                "output_namespace",
                "ontology_status",
                "temporal_relationship",
                "temporal_semantics",
                "temporal_window_present",
                "reason",
            ),
        )
        for source_key, count_key in (
            ("evidence", "evidence_count"),
            ("references", "reference_count"),
            ("matched_conditions", "matched_condition_count"),
        ):
            if isinstance(item.get(source_key), list):
                projected[count_key] = len(item[source_key])
        output.append(projected)
        if len(output) >= _COMPACT_SESSION_DETAIL_CORRELATION_LIMIT:
            break
    return output


def _compact_session_hypothesis_assessment(value: Any) -> Dict[str, Any]:
    """Expose the session-wide evidence ledger without raw command content."""

    source = value if isinstance(value, Mapping) else {}
    family_rows: list[Dict[str, Any]] = []
    for raw in source.get("semantic_families") or []:
        if not isinstance(raw, Mapping):
            continue
        family_rows.append({
            "semantic_family": str(raw.get("semantic_family") or "")[:80],
            "status": str(raw.get("status") or "")[:80],
            "observed_fact_count": raw.get("observed_fact_count", 0),
            "selector_match_count": raw.get("selector_match_count", 0),
            "selector_abstention_count": raw.get("selector_abstention_count", 0),
            "evidence_refs": [
                str(item)[:160]
                for item in (raw.get("evidence_refs") or [])[:50]
                if isinstance(item, str) and item
            ],
            "finding_ids": [
                str(item)[:160]
                for item in (raw.get("finding_ids") or [])[:20]
                if isinstance(item, str) and item
            ],
            "trusted_finding_ids": [
                str(item)[:160]
                for item in (raw.get("trusted_finding_ids") or [])[:20]
                if isinstance(item, str) and item
            ],
            "audit_only_finding_ids": [
                str(item)[:160]
                for item in (raw.get("audit_only_finding_ids") or [])[:20]
                if isinstance(item, str) and item
            ],
            "missing_evidence": [
                str(item)[:200]
                for item in (raw.get("missing_evidence") or [])[:20]
                if isinstance(item, str) and item
            ],
            "falsifiers": [
                {
                    "code": str(item.get("code") or "")[:100],
                    "semantic_family": str(item.get("semantic_family") or "")[:80],
                    "evidence_refs": [
                        str(ref)[:160]
                        for ref in (item.get("evidence_refs") or [])[:50]
                        if isinstance(ref, str) and ref
                    ],
                    "meaning": str(item.get("meaning") or "")[:240],
                }
                for item in (raw.get("falsifiers") or [])[:10]
                if isinstance(item, Mapping)
            ],
        })
    follow_on = source.get("follow_on_hypothesis")
    follow_on = follow_on if isinstance(follow_on, Mapping) else {}
    return {
        "schema_version": source.get("schema_version") or "session_hypothesis_assessment.v1",
        "scope": source.get("scope") or "session_wide",
        "authority": source.get("authority") or "evidence_bounded_non_authoritative",
        "status": source.get("status") or "unavailable",
        "semantic_families": family_rows[:20],
        "canonical_finding_ids": [
            str(item)[:160]
            for item in (source.get("canonical_finding_ids") or [])[:50]
            if isinstance(item, str) and item
        ],
        "audit_only_candidate_ids": [
            str(item)[:160]
            for item in (source.get("audit_only_candidate_ids") or [])[:50]
            if isinstance(item, str) and item
        ],
        "hypothesis_set_ids": [
            str(item)[:160]
            for item in (source.get("hypothesis_set_ids") or [])[:50]
            if isinstance(item, str) and item
        ],
        "follow_on_hypothesis": {
            "status": follow_on.get("status") or "insufficient_evidence",
            "reason": str(follow_on.get("reason") or "")[:600],
            "authority": follow_on.get("authority") or "non_authoritative_forecast_or_bounded_hypothesis",
            "evidence_gaps": [
                {
                    "text": str(item.get("text") or "")[:400],
                    "evidence_refs": [
                        str(ref)[:160]
                        for ref in (item.get("evidence_refs") or [])[:50]
                        if isinstance(ref, str) and ref
                    ],
                    "falsifier_codes": [
                        str(code)[:100]
                        for code in (item.get("falsifier_codes") or [])[:20]
                        if isinstance(code, str) and code
                    ],
                }
                for item in (follow_on.get("evidence_gaps") or [])[:20]
                if isinstance(item, Mapping)
            ],
        },
        "evidence_graph": dict(source.get("evidence_graph") or {}) if isinstance(source.get("evidence_graph"), Mapping) else {},
        "classification_summary": dict(source.get("classification_summary") or {}) if isinstance(source.get("classification_summary"), Mapping) else {},
        "missing_evidence": [
            str(item)[:200]
            for item in (source.get("missing_evidence") or [])[:50]
            if isinstance(item, str) and item
        ],
        "falsifiers": [
            {
                "code": str(item.get("code") or "")[:100],
                "semantic_family": str(item.get("semantic_family") or "")[:80],
                "evidence_refs": [
                    str(ref)[:160]
                    for ref in (item.get("evidence_refs") or [])[:50]
                    if isinstance(ref, str) and ref
                ],
                "meaning": str(item.get("meaning") or "")[:240],
            }
            for item in (source.get("falsifiers") or [])[:20]
            if isinstance(item, Mapping)
        ],
        "forecast_is_not_observed_evidence": source.get("forecast_is_not_observed_evidence") is True,
        "external_context_is_not_observed_evidence": source.get("external_context_is_not_observed_evidence") is True,
        "assessment_sha256": str(source.get("assessment_sha256") or "")[:64],
    }


def _compact_hypothesis_sets(value: Any) -> list[Dict[str, Any]]:
    """Expose bounded hypothesis meaning without raw command/event payloads."""

    output: list[Dict[str, Any]] = []
    for raw_set in value or []:
        if not isinstance(raw_set, Mapping):
            continue
        hypotheses: list[Dict[str, Any]] = []
        for raw_hypothesis in (raw_set.get("hypotheses") or [])[:8]:
            if not isinstance(raw_hypothesis, Mapping):
                continue
            hypotheses.append({
                "hypothesis_id": str(raw_hypothesis.get("hypothesis_id") or "")[:160],
                "statement": str(raw_hypothesis.get("statement") or "")[:1_000],
                "status": str(raw_hypothesis.get("status") or "")[:80],
                "artifact_paths": [
                    str(item)[:512]
                    for item in (raw_hypothesis.get("artifact_paths") or [])[:20]
                    if isinstance(item, str) and item
                ],
                "falsification_conditions": [
                    str(item)[:500]
                    for item in (raw_hypothesis.get("falsification_conditions") or [])[:20]
                    if isinstance(item, str) and item
                ],
            })
        output.append({
            "hypothesis_set_id": str(raw_set.get("hypothesis_set_id") or "")[:160],
            "question": str(raw_set.get("question") or "")[:1_000],
            "scope": str(raw_set.get("scope") or "")[:160],
            "hypotheses": hypotheses,
        })
        if len(output) >= 10:
            break
    return output


def _compact_session_detail_view(detail: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the bounded v1 public contract for the new detail endpoint."""

    session_payload = detail.get("session_payload")
    if not isinstance(session_payload, Mapping):
        session_payload = {}
    source_event_rows = detail.get("events_table_rows")
    if source_event_rows is None:
        source_event_rows = detail.get("events") or []
    command_count = count_command_events(source_event_rows)
    event_rows = event_views(list(source_event_rows)[:_COMPACT_SESSION_DETAIL_EVENT_LIMIT])
    overview = _redact_public_command_text(dict(detail.get("overview") or {}))
    overview["command_count"] = command_count
    raw_correlations = detail.get("session_ttp_correlations") or detail.get("correlated_ttp_hypotheses") or []
    authentication = detail.get("authentication_activity")
    authentication_view: Dict[str, Any] = {}
    if isinstance(authentication, Mapping):
        for field in (
            "schema_version",
            "authority",
            "attempt_count",
            "success_count",
            "failure_count",
            "first_attempt_at",
            "last_attempt_at",
            "username_visibility",
        ):
            value = authentication.get(field)
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                authentication_view[field] = value[:160] if isinstance(value, str) else value
        authentication_attempts = authentication.get("attempts")
        if isinstance(authentication_attempts, list):
            safe_attempts: list[Dict[str, Any]] = []
            for attempt in authentication_attempts[:50]:
                if not isinstance(attempt, Mapping):
                    continue
                outcome = attempt.get("outcome")
                if not isinstance(outcome, str) or outcome not in {"success", "failed"}:
                    continue
                safe_attempt: Dict[str, Any] = {"outcome": outcome}
                for field in ("timestamp", "username_visibility"):
                    value = attempt.get(field)
                    if isinstance(value, str) and value:
                        safe_attempt[field] = value[:160]
                attacker_username = attempt.get("attacker_username")
                if isinstance(attacker_username, str) and attacker_username:
                    safe_attempt["attacker_username"] = attacker_username[:128]
                safe_attempts.append(safe_attempt)
            authentication_view["attempts"] = safe_attempts
    result: Dict[str, Any] = {
        "ok": True,
        "schema_version": detail.get("schema_version") or "monitor.dashboard_session_detail.v1",
        "timestamp": detail.get("timestamp"),
        "session_id": detail.get("session_id"),
        "overview": overview,
        "source_geo": detail.get("source_geo") or {},
        "source_geo_context": detail.get("source_geo_context") or {},
        "observables": detail.get("observables") or [],
        "commands": _redact_public_command_text({"commands": detail.get("commands") or []})["commands"],
        "observed_trusted_ttps": _compact_trusted_observations(
            detail.get("observed_trusted_ttps") or session_payload.get("observed_trusted_ttps") or []
        ),
        "classification_events": _compact_classification_events(
            detail.get("classification_events") or session_payload.get("classification_events") or []
        ),
        "observed_tactic_path": _compact_observed_tactic_path(
            detail.get("observed_tactic_path") or session_payload.get("observed_tactic_path") or []
        ),
        "correlated_ttp_hypotheses": _compact_correlations(raw_correlations),
        "hypothesis_sets": _compact_hypothesis_sets(
            detail.get("hypothesis_sets")
        ),
        "session_hypothesis_assessment": _compact_session_hypothesis_assessment(
            detail.get("session_hypothesis_assessment")
        ),
        "session_ttp_correlation_summary": _pick(
            detail.get("session_ttp_correlation_summary") or {},
            (
                "status",
                "correlation_authority",
                "correlation_count",
                "observed_trusted_ttp_count",
                "confidence_semantics",
                "temporal_semantics",
                "output_namespace",
                "observed_output_namespace",
                "correlation_output_namespace",
                "prediction_input_count",
            ),
        ),
        "tactics": detail.get("tactics") or [],
        "ttps": detail.get("ttps") or [],
        "enrichment_status": detail.get("enrichment_status") or {},
        "authentication_activity": authentication_view,
        "ensemble_evidence": detail.get("ensemble_evidence") or {},
        "session_ttp_advisory": detail.get("session_ttp_advisory") or {},
        "next_distinct_prediction": detail.get("next_distinct_prediction") or {},
        "session": {
            "session_id": session_payload.get("session_id"),
            "sensor_id": session_payload.get("sensor_id") or session_payload.get("sensor"),
            "src_ip": session_payload.get("src_ip"),
            "start_time": session_payload.get("start_time"),
            "duration": session_payload.get("duration"),
            "is_ended": session_payload.get("is_ended"),
            "command_count": command_count,
            "analysis_status": session_payload.get("analysis_status") or session_payload.get("status"),
        },
        "events": event_rows,
        "prediction_snapshots": [
            api_row_view("prediction_snapshots", row)
            for row in (detail.get("prediction_snapshots") or [])[:50]
        ],
        "latest_prediction_snapshot": api_row_view(
            "prediction_snapshots", (detail.get("prediction_snapshots") or [])[0]
        ) if detail.get("prediction_snapshots") else {},
        "analysis_jobs": [
            api_row_view("analysis_jobs", row)
            for row in (detail.get("analysis_jobs") or [])[:50]
        ],
        "reports": [
            api_row_view("reports", row)
            for row in (detail.get("reports") or [])[:50]
        ],
        "report_summary": detail.get("report_summary") or {},
        "response_guidance": _compact_session_guidance(detail.get("response_guidance")),
        "counts": {
            "events": len(source_event_rows),
            "events_returned": len(event_rows),
            "events_truncated": len(source_event_rows) > len(event_rows),
            "classification_events": len(detail.get("classification_events") or []),
            "trusted_observations": len(detail.get("observed_trusted_ttps") or []),
            "correlations": len(raw_correlations),
        },
        "errors": detail.get("errors") or {},
    }
    return public_payload(_redact_public_command_text(result))


def session_detail_view(
    detail: Mapping[str, Any],
    *,
    compact: bool = False,
) -> Dict[str, Any]:
    """Return useful session analysis without raw events or storage documents."""
    if not detail.get("ok"):
        return public_payload(dict(detail))
    if compact:
        return _compact_session_detail_view(detail)
    session_payload = detail.get("session_payload")
    if not isinstance(session_payload, Mapping):
        session_payload = {}
    source_event_rows = detail.get("events_table_rows")
    if source_event_rows is None:
        source_event_rows = detail.get("events") or []
    command_count = count_command_events(source_event_rows)
    event_rows = event_views(source_event_rows)
    overview = _redact_public_command_text(dict(detail.get("overview") or {}))
    overview["command_count"] = command_count
    public_commands = _redact_public_command_text(
        {"commands": detail.get("commands") or []}
    )["commands"]
    raw_correlations = detail.get("session_ttp_correlations") or []
    public_correlations = []
    for item in raw_correlations:
        if not isinstance(item, Mapping):
            continue
        projected = dict(item)
        projected["confidence_semantics"] = resolve_confidence_semantics(
            item.get("confidence_semantics")
        )
        public_correlations.append(projected)
    raw_correlation_summary = detail.get("session_ttp_correlation_summary") or {}
    public_correlation_summary = (
        dict(raw_correlation_summary)
        if isinstance(raw_correlation_summary, Mapping)
        else {}
    )
    public_correlation_summary["confidence_semantics"] = resolve_confidence_semantics(
        public_correlation_summary.get("confidence_semantics")
    )
    observed_trusted_ttps = _redact_public_command_text(
        detail.get("observed_trusted_ttps")
        or session_payload.get("observed_trusted_ttps")
        or []
    )
    output: Dict[str, Any] = {
        "ok": True,
        "timestamp": detail.get("timestamp"),
        "session_id": detail.get("session_id"),
        "overview": overview,
        "source_geo": detail.get("source_geo") or {},
        "source_geo_context": detail.get("source_geo_context") or {},
        "observables": detail.get("observables") or [],
        "commands": public_commands,
        "classification_events": _redact_public_command_text(
            [
                _normalize_inactive_classifier_event_for_public(item)
                for item in (detail.get("classification_events") or [])
                if isinstance(item, Mapping)
            ]
        ),
        "observed_trusted_ttps": observed_trusted_ttps,
        "correlated_ttp_hypotheses": public_correlations,
        "hypothesis_sets": _compact_hypothesis_sets(
            detail.get("hypothesis_sets")
        ),
        "session_hypothesis_assessment": _compact_session_hypothesis_assessment(
            detail.get("session_hypothesis_assessment")
        ),
        "session_ttp_correlations": public_correlations,
        "session_ttp_correlation_summary": public_correlation_summary,
        "tactics": detail.get("tactics") or [],
        "ttps": detail.get("ttps") or [],
        "ttp_command_map": _redact_public_command_text(
            detail.get("ttp_command_map") or {}
        ),
        "enrichment_status": detail.get("enrichment_status") or {},
        "ensemble_evidence": detail.get("ensemble_evidence") or {},
        "session_ttp_advisory": detail.get("session_ttp_advisory") or {},
        "next_distinct_prediction": detail.get("next_distinct_prediction") or {},
        "session": {
            "session_id": session_payload.get("session_id"),
            "sensor_id": session_payload.get("sensor_id") or session_payload.get("sensor"),
            "src_ip": session_payload.get("src_ip"),
            "start_time": session_payload.get("start_time"),
            "duration": session_payload.get("duration"),
            "is_ended": session_payload.get("is_ended"),
            "command_count": command_count,
            "analysis_status": session_payload.get("analysis_status") or session_payload.get("status"),
        },
        # ``events`` is the canonical session-detail contract. Keep the
        # historical name as a read-only alias for older monitor consumers.
        "events": event_rows,
        "events_table_rows": event_rows,
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
    if detail.get("schema_version"):
        output["schema_version"] = detail.get("schema_version")
    # Apply the command-specific boundary after assembling every consumer
    # field.  Correlations and legacy compatibility structures can carry a
    # command-shaped value even when the primary fields are empty.
    return public_payload(_redact_public_command_text(output))


def sanitize_request_target(target: str) -> str:
    """Redact sensitive query values from a request target before logging."""
    return sanitize_url(str(target or ""))[:2048]
