"""Production report artifacts: JSON, STIX 2.1, and PDF/Markdown fallback."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
import uuid
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

from production.utils.config import ProductionConfig
from production.utils.sensitive_data import (
    redact_exception_for_log,
    redact_for_artifact,
)
from production.utils.serialization import stable_id, stable_json
from production.reporting.response_guidance_v3 import validate_response_guidance_v3
from production.reporting.artifact_privacy import sanitize_artifact_boundary
from production.enrichment.external_ti_session import TI_STATUS_REASON_TEXT
from production.ensemble.session_ttp_advisory import summarize_session_model1_ttp


TI_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "my-ti-pipeline.local")

def _ti_display_status(value: Any) -> str:
    """Render the canonical ETI state without inventing report vocabulary.

    The report is a durable projection of the API read model.  Translating
    states here made the same session appear to have different ETI outcomes
    in the API and PDF, so normalization is deliberately limited to casing.
    """

    normalized = str(value or "NOT_AVAILABLE").strip().upper()
    return normalized


def _latest_ti_lookup_at(external_context: Any) -> Any:
    """Return the newest recorded provider retrieval or source-IP cache lookup."""

    if not isinstance(external_context, dict):
        return None
    freshness = external_context.get("freshness")
    freshness = freshness if isinstance(freshness, dict) else {}
    summary = external_context.get("external_ti_summary")
    summary = summary if isinstance(summary, dict) else external_context
    candidates = [
        freshness.get("latest_retrieved_at"),
        summary.get("source_ip_cache_latest_lookup_at"),
    ]
    parsed_candidates = []
    for value in candidates:
        if not isinstance(value, str) or not value.strip():
            continue
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        parsed_candidates.append((parsed.astimezone(timezone.utc), value))
    if parsed_candidates:
        return max(parsed_candidates, key=lambda item: item[0])[1]
    return next(
        (value for value in candidates if isinstance(value, str) and value.strip()),
        None,
    )


class _PDFExportUnavailable(RuntimeError):
    """Raised when the optional PDF renderer is not installed."""


class _ReportsDirectoryIdentityChanged(ValueError):
    """Raised when the configured path no longer names the trusted directory."""


def _safe_artifact_mapping(value: Any, label: str) -> Dict[str, Any]:
    """Return a redacted mapping or fail without exposing the input."""

    if (
        label == "report"
        and isinstance(value, dict)
        and value.get("schema_version") == "session_assessment.v4"
    ):
        # V4 has already been redacted before its evidence digest and content
        # IDs are computed. Re-redacting at each consumer can alter an
        # otherwise valid canonical snapshot and invalidate its guidance hash.
        from production.reporting.session_assessment_v4 import (
            validate_session_assessment_v4,
        )

        validate_session_assessment_v4(value, raise_on_error=True)
        # Canonical evidence and the response-guidance binding contain the
        # exact content whose hashes/IDs were just verified.  Applying the
        # command-text projection recursively to those content-addressed
        # branches would change their hashes and make a valid report appear
        # tampered.  Preserve them byte-for-byte and sanitize only the
        # non-authoritative compatibility/context branches.
        safe = sanitize_artifact_boundary(value)
        safe["canonical_evidence"] = deepcopy(value["canonical_evidence"])
        safe_guidance = deepcopy(value["response_guidance_v3"])
        if isinstance(safe_guidance.get("non_authoritative_context"), dict):
            safe_guidance["non_authoritative_context"] = sanitize_artifact_boundary(
                safe_guidance["non_authoritative_context"]
            )
        safe["response_guidance_v3"] = safe_guidance
        return safe
    try:
        redacted = redact_for_artifact(value)
    except Exception:
        raise ValueError(f"{label} redaction failed") from None
    redacted = sanitize_artifact_boundary(redacted)
    if not isinstance(redacted, dict):
        raise TypeError(f"{label} must redact to an object")
    return redacted


def _safe_artifact_text(value: Any, label: str) -> str:
    try:
        redacted = redact_for_artifact(str(value))
    except Exception:
        raise ValueError(f"{label} redaction failed") from None
    if not isinstance(redacted, str):
        raise TypeError(f"{label} must redact to text")
    return redacted


def _safe_artifact_error(exc: BaseException) -> str:
    return redact_exception_for_log(exc)


@dataclass(frozen=True)
class _ReportsDirectory:
    path: Path
    descriptor: int


def _directory_open_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _open_reports_directory(
    configured_path: Any,
    *,
    create_leaf: bool,
) -> _ReportsDirectory:
    """Open a private directory by component and keep the trusted fd alive."""

    directory_descriptor = -1
    try:
        configured = str(configured_path or "").strip()
        if not configured:
            raise ValueError
        output_dir = Path(os.path.abspath(configured))
        working_directory = Path(os.path.abspath(os.getcwd()))
        if output_dir == Path("/") or output_dir == working_directory:
            raise ValueError
        components = output_dir.parts[1:]
        if not components:
            raise ValueError
        flags = _directory_open_flags()
        directory_descriptor = os.open(os.sep, flags)
        for index, component in enumerate(components):
            is_leaf = index == len(components) - 1
            try:
                next_descriptor = os.open(
                    component,
                    flags,
                    dir_fd=directory_descriptor,
                )
            except FileNotFoundError:
                if not (create_leaf and is_leaf):
                    raise
                os.mkdir(component, mode=0o700, dir_fd=directory_descriptor)
                next_descriptor = os.open(
                    component,
                    flags,
                    dir_fd=directory_descriptor,
                )
                os.fchmod(next_descriptor, 0o700)
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        metadata = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise PermissionError
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise PermissionError
        return _ReportsDirectory(output_dir, directory_descriptor)
    except Exception:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
        raise ValueError("reports directory preparation failed") from None


def _assert_reports_directory_identity(directory: _ReportsDirectory) -> None:
    """Verify that the configured path still resolves to the held directory."""

    reopened: Optional[_ReportsDirectory] = None
    try:
        reopened = _open_reports_directory(directory.path, create_leaf=False)
        trusted_metadata = os.fstat(directory.descriptor)
        current_metadata = os.fstat(reopened.descriptor)
        if (
            trusted_metadata.st_dev,
            trusted_metadata.st_ino,
        ) != (
            current_metadata.st_dev,
            current_metadata.st_ino,
        ):
            raise _ReportsDirectoryIdentityChanged
    except _ReportsDirectoryIdentityChanged:
        raise _ReportsDirectoryIdentityChanged(
            "reports directory identity changed"
        ) from None
    except Exception:
        raise _ReportsDirectoryIdentityChanged(
            "reports directory identity changed"
        ) from None
    finally:
        if reopened is not None:
            os.close(reopened.descriptor)


@contextmanager
def _prepare_reports_directory(
    configured_path: Any,
) -> Iterator[_ReportsDirectory]:
    directory = _open_reports_directory(configured_path, create_leaf=True)
    try:
        yield directory
    finally:
        os.close(directory.descriptor)


@contextmanager
def _reports_directory_handle(
    output_dir: Any,
) -> Iterator[_ReportsDirectory]:
    if isinstance(output_dir, _ReportsDirectory):
        yield output_dir
        return
    directory = _open_reports_directory(output_dir, create_leaf=False)
    try:
        yield directory
    finally:
        os.close(directory.descriptor)


def _safe_name(value: Any) -> str:
    text = str(value)
    return "".join(
        ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in text
    )[:120] or "unknown"


_ARTIFACT_VERSION_PATTERN = re.compile(r"^artifact_[0-9a-f]{32}$")
_INTEGRITY_MANIFEST_PATTERN = re.compile(
    r"^artifact_[0-9a-f]{32}_artifact_manifest_([0-9a-f]{64})\.json$"
)


def _artifact_version_id(
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
) -> str:
    """Derive a retry-stable version before artifact paths are attached."""

    if report.get("schema_version") == "session_assessment.v4":
        provenance = report.get("provenance") or {}
        evidence_sha256 = str(provenance.get("evidence_sha256") or "").strip()
        assessment_id = str(report.get("assessment_id") or "").strip()
        if assessment_id and evidence_sha256:
            return stable_id(
                "artifact",
                {
                    "contract": "canonical_report_artifacts.v2",
                    "schema_version": "session_assessment.v4",
                    "assessment_id": assessment_id,
                    "evidence_sha256": evidence_sha256,
                    "session_id": (
                        session_payload.get("session_id")
                        or report.get("session_id")
                        or "unknown"
                    ),
                },
            )

    report_basis = dict(report)
    report_basis.pop("artifacts", None)
    session_basis = dict(session_payload)
    session_basis.pop("artifacts", None)
    return stable_id(
        "artifact",
        {
            "report": report_basis,
            "session": session_basis,
        },
    )


def _resolve_artifact_version(
    artifact_version: str,
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
) -> str:
    if artifact_version:
        if not _ARTIFACT_VERSION_PATTERN.fullmatch(artifact_version):
            raise ValueError("artifact version is invalid")
        return artifact_version
    return _artifact_version_id(report, session_payload)


def _verified_artifact_path(
    directory: _ReportsDirectory,
    filename: str,
) -> str:
    _assert_reports_directory_identity(directory)
    return str(directory.path / filename)


@contextmanager
def _private_artifact_path(
    directory: _ReportsDirectory,
    filename: str,
) -> Iterator[Path]:
    """Build and replace an artifact relative to a trusted directory fd."""

    if Path(filename).name != filename:
        raise ValueError("artifact filename must not contain path components")
    temporary_name = ""
    file_descriptor = -1
    create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    create_flags |= getattr(os, "O_CLOEXEC", 0)
    create_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        _assert_reports_directory_identity(directory)
        for _attempt in range(10):
            temporary_name = f".{filename}.{uuid.uuid4().hex}.tmp"
            try:
                file_descriptor = os.open(
                    temporary_name,
                    create_flags,
                    0o600,
                    dir_fd=directory.descriptor,
                )
                break
            except FileExistsError:
                continue
        if file_descriptor < 0:
            raise FileExistsError("could not allocate private artifact temporary file")
        os.fchmod(file_descriptor, 0o600)
        os.close(file_descriptor)
        file_descriptor = -1
        temporary_path = (
            Path("/proc/self/fd")
            / str(directory.descriptor)
            / temporary_name
        )
        yield temporary_path
        _assert_reports_directory_identity(directory)
        verify_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        verify_flags |= getattr(os, "O_NOFOLLOW", 0)
        file_descriptor = os.open(
            temporary_name,
            verify_flags,
            dir_fd=directory.descriptor,
        )
        try:
            os.fsync(file_descriptor)
            os.fchmod(file_descriptor, 0o600)
        finally:
            os.close(file_descriptor)
            file_descriptor = -1
        os.replace(
            temporary_name,
            filename,
            src_dir_fd=directory.descriptor,
            dst_dir_fd=directory.descriptor,
        )
        os.fsync(directory.descriptor)
        _assert_reports_directory_identity(directory)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=directory.descriptor)
            except FileNotFoundError:
                pass


def _stix_timestamp(
    value: str,
    fallback: str = "1970-01-01T00:00:00Z",
) -> str:
    if not value:
        return fallback
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return fallback


def _artifact_timestamp(
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
) -> str:
    """Choose a source-bound timestamp without consulting the wall clock."""

    if report.get("schema_version") == "session_assessment.v4":
        evidence = report.get("canonical_evidence") or {}
        source_timestamps = [
            _stix_timestamp(str(item.get("timestamp") or ""), fallback="")
            for collection in (
                "observations",
                "transfer_observations",
                "direct_cowrie_events",
                "trusted_attck_candidates",
            )
            for item in evidence.get(collection) or []
            if isinstance(item, dict) and item.get("timestamp")
        ]
        source_timestamps = [
            value for value in source_timestamps if value
        ]
        if source_timestamps:
            return max(source_timestamps)
        for value in (
            session_payload.get("end_time"),
            session_payload.get("updated_at"),
            session_payload.get("start_time"),
        ):
            if str(value or "").strip():
                return _stix_timestamp(str(value))
        return "1970-01-01T00:00:00Z"

    for value in (
        report.get("generated_at"),
        session_payload.get("end_time"),
        session_payload.get("updated_at"),
        session_payload.get("start_time"),
    ):
        if str(value or "").strip():
            return _stix_timestamp(str(value))
    return "1970-01-01T00:00:00Z"


def _stix_source_report_sha256(report: Dict[str, Any]) -> str:
    """Hash the retry-stable report projection represented in STIX."""

    basis = deepcopy(report)
    if basis.get("schema_version") == "session_assessment.v4":
        for key in (
            "artifacts",
            "generated_at",
            "non_authoritative_context",
        ):
            basis.pop(key, None)
        guidance = basis.get("response_guidance_v3")
        if isinstance(guidance, dict):
            guidance = deepcopy(guidance)
            guidance.pop("generated_at", None)
            guidance.pop("non_authoritative_context", None)
            basis["response_guidance_v3"] = guidance
    return hashlib.sha256(
        stable_json(basis).encode("utf-8")
    ).hexdigest()


def _ioc_items(ioc_summary: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for key in ("ips", "urls", "domains", "hashes", "ports"):
        for item in ioc_summary.get(key, []) or []:
            yield item


def _layer_items(report: Dict[str, Any], layer_name: str) -> List[Dict[str, Any]]:
    layers = report.get("threat_evidence_layers") or {}
    layer = layers.get(layer_name) if isinstance(layers, dict) else {}
    items = layer.get("items") if isinstance(layer, dict) else []
    return [item for item in items or [] if isinstance(item, dict)]


def _evidence_layer_summary_lines(report: Dict[str, Any]) -> List[str]:
    layers = report.get("threat_evidence_layers") or {}
    if not isinstance(layers, dict):
        return []
    summary = layers.get("summary") or {}
    if not isinstance(summary, dict):
        summary = {}
    return [
        f"Direct command TTPs: {summary.get('direct_command_ttp_count', 0)}",
        f"Session-correlated TTPs: {summary.get('session_correlated_ttp_count', 0)}",
        f"Prediction-only hypotheses: {summary.get('prediction_hypothesis_count', 0)}",
    ]


def _evidence_reference_summary(values: Any) -> str:
    """Render a bounded, content-addressed reference-set summary."""

    references = sorted({
        str(item).strip()
        for item in (values or [])
        if str(item).strip()
    })
    if not references:
        return "Unavailable"
    digest = hashlib.sha256(
        stable_json(sorted(references)).encode("utf-8")
    ).hexdigest()
    examples = ", ".join(
        item if len(item) <= 26 else f"{item[:25]}…"
        for item in references[:3]
    )
    remainder = len(references) - min(len(references), 3)
    suffix = f"; +{remainder} more" if remainder else ""
    return (
        f"{len(references)} refs; examples: {examples}{suffix}; "
        f"set SHA-256: {digest}"
    )


def _report_prediction_context(
    snapshot: Any,
    session_id: Any,
) -> Dict[str, Any]:
    """Return a bounded, exact-session forecast projection for the report.

    Prediction snapshots are optional presentation context.  This helper is
    intentionally strict: a snapshot without an exact session binding, or a
    snapshot whose integrity validator reported an error, is not rendered.
    Raw features, probabilities, model paths, and arbitrary nested payloads
    are never copied into the report projection.
    """

    if not isinstance(snapshot, dict):
        return {}
    expected_session = str(session_id or "").strip()
    payload = snapshot.get("payload") if isinstance(snapshot.get("payload"), dict) else snapshot
    if not isinstance(payload, dict) or not expected_session:
        return {}
    snapshot_session = str(
        snapshot.get("session_id")
        or payload.get("session_id")
        or payload.get("sequence_id")
        or ""
    ).strip()
    if snapshot_session != expected_session:
        return {}
    integrity_errors = snapshot.get("integrity_errors") or payload.get("integrity_errors")
    if integrity_errors:
        return {}

    def _bounded_text(value: Any, limit: int) -> str:
        if value in (None, ""):
            return ""
        try:
            sanitized = _safe_artifact_text(value, "prediction_context")
        except (TypeError, ValueError):
            return ""
        if not sanitized or sanitized == "[REDACTED]":
            return ""
        return sanitized[:limit]

    def _bounded_digest(*values: Any) -> str:
        """Keep only an explicitly shaped SHA-256 identity in the report."""

        for value in values:
            text = _bounded_text(value, 80).strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", text):
                return text
        return ""

    def _bounded_identity(*values: Any) -> str:
        """Keep a short binding identity, never an arbitrary nested payload."""

        for value in values:
            text = _bounded_text(value, 160).strip()
            if text:
                return text
        return ""

    raw_ranking = payload.get("final_ranking")
    if not isinstance(raw_ranking, list):
        output = payload.get("next_behavior_output")
        raw_ranking = output.get("ranked_tactics") if isinstance(output, dict) else []
    ranking: List[Dict[str, Any]] = []
    for index, item in enumerate(raw_ranking or [], start=1):
        if isinstance(item, dict):
            label = item.get("tactic") or item.get("label") or item.get("prediction")
            rank = item.get("rank") or index
        else:
            label = item
            rank = index
        label_text = _bounded_text(label, 120).strip()
        if not label_text:
            continue
        ranking.append({"rank": rank, "label": label_text[:120]})
        if len(ranking) >= 5:
            break

    prediction_values = payload.get("prediction")
    if not isinstance(prediction_values, list):
        output = payload.get("next_behavior_output")
        prediction_values = output.get("prediction_set") if isinstance(output, dict) else []
    predictions = [
        _bounded_text(item, 120).strip()
        for item in (prediction_values or [])
        if _bounded_text(item, 120).strip()
    ][:5]
    context = {
        "status": _bounded_text(payload.get("prediction_status") or "UNAVAILABLE", 80).upper(),
        "reason": _bounded_text(payload.get("prediction_status_reason"), 240),
        "predictions": predictions,
        "ranking": ranking,
        "generated_at": (
            payload.get("generated_at")
            or snapshot.get("created_at")
            or snapshot.get("recorded_at")
            or ""
        ),
        "snapshot_id": _bounded_text(
            payload.get("snapshot_id")
            or snapshot.get("snapshot_id")
            or snapshot.get("prediction_id")
            or "",
            160,
        ).strip(),
        "authority": "NON_AUTHORITATIVE_FORECAST_ONLY",
    }
    # These are presentation-only binding identities.  They are copied only
    # after exact session binding and snapshot-integrity checks above; raw
    # features, checkpoint paths, scores, and arbitrary model payloads stay
    # outside the report boundary.
    for key, candidates in {
        "run_id": (
            payload.get("run_id"),
            payload.get("completed_run_id"),
            snapshot.get("run_id"),
        ),
        "measurement_id": (
            payload.get("measurement_id"),
            snapshot.get("measurement_id"),
        ),
        "episode_id": (
            payload.get("episode_id"),
            snapshot.get("episode_id"),
        ),
        "model_id": (
            payload.get("model_id"),
            payload.get("model_identifier"),
        ),
    }.items():
        identity = _bounded_identity(*candidates)
        if identity:
            context[key] = identity
    model_digest = _bounded_digest(
        payload.get("model_artifact_sha256"),
        payload.get("artifact_sha256"),
        payload.get("model_sha256"),
        snapshot.get("model_artifact_sha256"),
        snapshot.get("artifact_sha256"),
    )
    feature_digest = _bounded_digest(
        payload.get("feature_contract_sha256"),
        payload.get("feature_contract_digest"),
        snapshot.get("feature_contract_sha256"),
    )
    if model_digest:
        context["model_artifact_sha256"] = model_digest
    if feature_digest:
        context["feature_contract_sha256"] = feature_digest
    return context


def _trusted_ttp_ids(report: Dict[str, Any], session_payload: Dict[str, Any]) -> List[str]:
    if report.get("schema_version") == "session_assessment.v4":
        evidence = report.get("canonical_evidence") or {}
        observed = evidence.get("observed_trusted_ttps") or []
        if observed:
            return list(dict.fromkeys(
                str(item.get("technique_id") or "").strip()
                for item in observed
                if isinstance(item, dict) and str(item.get("technique_id") or "").strip()
            ))
        return list(dict.fromkeys(
            str(item.get("technique_id") or "").strip()
            for item in evidence.get("trusted_attck_candidates") or []
            if isinstance(item, dict) and str(item.get("technique_id") or "").strip()
        ))
    observed = report.get("observed_behavior") or {}
    candidates = (
        observed.get("observed_trusted_ttps") or observed.get("trusted_attck_candidates")
        if isinstance(observed, dict)
        else []
    )
    if report.get("schema_version") == "threat_hypothesis.v2":
        return list(dict.fromkeys(
            str(item.get("technique_id") or "").strip()
            for item in candidates or []
            if isinstance(item, dict) and str(item.get("technique_id") or "").strip()
        ))
    return list(dict.fromkeys(
        str(value).strip()
        for value in (session_payload.get("ttps", []) or report.get("ttps", []) or [])
        if str(value).strip()
    ))


def write_json_report(
    report: Dict[str, Any],
    session_id: str,
    output_dir: Path,
    *,
    artifact_version: str = "",
) -> str:
    safe_report = _safe_artifact_mapping(report, "report")
    safe_session_id = _safe_artifact_text(session_id, "session_id")
    version = _resolve_artifact_version(
        artifact_version,
        safe_report,
        {"session_id": safe_session_id},
    )
    filename = f"{_safe_name(safe_session_id)}_{version}_report.json"
    rendered = json.dumps(
        safe_report,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )
    with _reports_directory_handle(output_dir) as directory:
        with _private_artifact_path(directory, filename) as temporary_path:
            temporary_path.write_text(rendered, encoding="utf-8")
        return _verified_artifact_path(directory, filename)


def _stix_id(object_type: str, key: str) -> str:
    return f"{object_type}--{uuid.uuid5(TI_NAMESPACE, object_type + ':' + key)}"


def _append_stix_object(
    objects: List[Dict[str, Any]],
    report_obj: Dict[str, Any],
    obj: Dict[str, Any],
    seen_ids: set[str],
    *,
    reference_from_report: bool = True,
) -> None:
    object_id = str(obj.get("id") or "")
    if not object_id or object_id in seen_ids:
        return
    seen_ids.add(object_id)
    objects.append(obj)
    if reference_from_report and object_id not in report_obj["object_refs"]:
        report_obj["object_refs"].append(object_id)


def _trusted_recommendation_actions(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    guidance = report.get("response_guidance_v3")
    if not isinstance(guidance, dict) or guidance.get("schema_version") != "response_guidance.v3":
        return []
    if validate_response_guidance_v3(guidance):
        return []
    return [
        item for item in guidance.get("advisory_actions") or []
        if isinstance(item, dict)
        and item.get("requires_manual_approval") is True
        and item.get("safe_to_auto_execute") is False
        and item.get("execution_integration") == "not_implemented"
    ]


def _external_references(raw_refs: Any) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []
    for ref in raw_refs or []:
        if not isinstance(ref, dict):
            continue
        name = str(ref.get("name") or ref.get("source_name") or ref.get("title") or "reference").strip()
        url = str(ref.get("url") or "").strip()
        external_id = str(ref.get("external_id") or ref.get("id") or "").strip()
        out = {"source_name": name}
        if url:
            out["url"] = url
        if external_id:
            out["external_id"] = external_id
        refs.append(out)
    return refs


def _extract_ttp_ids_from_action(action: Dict[str, Any]) -> List[str]:
    values: List[str] = []
    for key in ("ttp", "ttps", "technique", "techniques", "mitre_techniques"):
        raw = action.get(key)
        if isinstance(raw, list):
            values.extend(str(item) for item in raw)
        elif raw:
            values.append(str(raw))
    for ref in action.get("references") or []:
        if not isinstance(ref, dict):
            continue
        values.extend(str(ref.get(key) or "") for key in ("external_id", "id", "name", "url"))
    values.extend(str(item) for item in action.get("evidence") or [])
    joined = "\n".join(values)
    ttps = []
    for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", joined, flags=re.IGNORECASE):
        main = match.upper().split(".", 1)[0]
        if main not in ttps:
            ttps.append(main)
    return ttps


def _sco_for_ioc(ioc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ioc_type = str(ioc.get("type") or "").strip().lower()
    value = str(ioc.get("value") or "").strip()
    if not value:
        return None
    if ioc_type in {"ipv4", "ipv6"}:
        object_type = "ipv6-addr" if ioc_type == "ipv6" else "ipv4-addr"
        return {
            "type": object_type,
            "spec_version": "2.1",
            "id": _stix_id(object_type, value),
            "value": value,
        }
    if ioc_type == "domain":
        return {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": _stix_id("domain-name", value),
            "value": value,
        }
    if ioc_type == "url":
        return {
            "type": "url",
            "spec_version": "2.1",
            "id": _stix_id("url", value),
            "value": value,
        }
    if ioc_type in {"sha256", "sha1", "md5"}:
        return {
            "type": "file",
            "spec_version": "2.1",
            "id": _stix_id("file", ioc_type + ":" + value),
            "hashes": {ioc_type.upper(): value},
        }
    return None


def _build_identity(now: str, session_payload: Dict[str, Any]) -> Dict[str, Any]:
    sensor = str(session_payload.get("sensor") or session_payload.get("sensor_id") or "honeypot").strip()
    identity_id = _stix_id("identity", "honeypot-sensor:" + sensor)
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": f"Honeypot sensor {sensor}",
        "identity_class": "system",
    }


def build_stix_bundle(report: Dict[str, Any], session_payload: Dict[str, Any]) -> Dict[str, Any]:
    # Validate and capture trusted policy actions from the canonical report
    # before the artifact privacy projection.  V4 canonical evidence is
    # content-addressed; the privacy projection intentionally redacts command
    # text inside typed facts, so validating the projected copy would make an
    # otherwise trusted action disappear merely because it was serialized for
    # a public artifact.  Only the small, policy-derived action fields used by
    # STIX are carried forward and are redacted independently below.
    trusted_actions = _trusted_recommendation_actions(report)
    report = _safe_artifact_mapping(report, "report")
    session_payload = _safe_artifact_mapping(session_payload, "session")
    now = _artifact_timestamp(report, session_payload)
    session_id = session_payload.get("session_id", "unknown")
    artifact_version = _artifact_version_id(report, session_payload)
    objects: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    report_obj = {
        "type": "report",
        "spec_version": "2.1",
        "id": _stix_id("report", artifact_version),
        "created": now,
        "modified": now,
        "name": f"Automated Threat Intelligence Report - {session_id}",
        "published": now,
        "report_types": ["threat-actor-activity"],
        "object_refs": [],
        "x_honeypot_artifact_version": artifact_version,
        "x_honeypot_source_report_sha256": (
            _stix_source_report_sha256(report)
        ),
    }

    if report.get("schema_version") == "session_assessment.v4":
        provenance = report.get("provenance") or {}
        for finding in report.get("behavioral_findings") or []:
            if not isinstance(finding, dict):
                continue
            finding_id = _stix_id(
                "x-honeypot-behavioral-finding",
                str(finding.get("finding_id") or stable_json(finding)),
            )
            _append_stix_object(objects, report_obj, {
                "type": "x-honeypot-behavioral-finding",
                "spec_version": "2.1",
                "id": finding_id,
                "created": now,
                "modified": now,
                "x_honeypot_finding_id": finding.get("finding_id") or "",
                "x_honeypot_finding_type": finding.get("finding_type") or "",
                "x_honeypot_statement": finding.get("statement") or "",
                "x_honeypot_status": finding.get("status") or "",
                "x_honeypot_evidence_refs": finding.get("evidence_refs") or [],
                "x_honeypot_relationship_refs": finding.get("relationship_refs") or [],
                "x_honeypot_evidence_sha256": provenance.get("evidence_sha256") or "",
            }, seen_ids)
        for hypothesis_set in report.get("hypothesis_sets") or []:
            if not isinstance(hypothesis_set, dict):
                continue
            set_id = _stix_id(
                "x-honeypot-hypothesis-set",
                str(hypothesis_set.get("hypothesis_set_id") or stable_json(hypothesis_set)),
            )
            _append_stix_object(objects, report_obj, {
                "type": "x-honeypot-hypothesis-set",
                "spec_version": "2.1",
                "id": set_id,
                "created": now,
                "modified": now,
                "x_honeypot_hypothesis_set_id": hypothesis_set.get("hypothesis_set_id") or "",
                "x_honeypot_question": hypothesis_set.get("question") or "",
                "x_honeypot_hypotheses": hypothesis_set.get("hypotheses") or [],
                "x_honeypot_evidence_sha256": provenance.get("evidence_sha256") or "",
            }, seen_ids)

    ttp_obj_map = {}
    for tid in sorted(set(_trusted_ttp_ids(report, session_payload))):
        ap_id = f"attack-pattern--{uuid.uuid5(TI_NAMESPACE, 'attack-pattern:' + tid)}"
        attack_pattern = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created": now,
            "modified": now,
            "name": tid,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
            }],
        }
        ttp_obj_map[tid] = attack_pattern
        _append_stix_object(objects, report_obj, attack_pattern, seen_ids)

    legacy_actor_matches = [] if report.get("schema_version") == "threat_hypothesis.v2" else report.get("actor_matches", []) or []
    for actor in legacy_actor_matches:
        actor_name = actor.get("actor", "Unknown")
        actor_id = f"threat-actor--{uuid.uuid5(TI_NAMESPACE, 'actor:' + actor_name)}"
        actor_obj = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": actor_id,
            "created": now,
            "modified": now,
            "name": actor_name,
            "confidence": int(actor.get("score", 0)),
            "labels": ["apt"],
            "description": f"Matched: {', '.join(actor.get('matched_ttps', []))}",
            "x_honeypot_attribution_warning": "TTP overlap only; not confirmed named-actor attribution.",
        }
        _append_stix_object(objects, report_obj, actor_obj, seen_ids)
        for tid in actor.get("matched_ttps", []):
            if tid in ttp_obj_map:
                relationship_id = f"relationship--{uuid.uuid5(TI_NAMESPACE, 'rel:' + actor_id + ':' + ttp_obj_map[tid]['id'])}"
                _append_stix_object(objects, report_obj, {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": relationship_id,
                    "created": now,
                    "modified": now,
                    "relationship_type": "uses",
                    "source_ref": actor_id,
                    "target_ref": ttp_obj_map[tid]["id"],
                }, seen_ids, reference_from_report=False)

    ioc_summary = report.get("ioc_summary") or session_payload.get("ioc_summary") or {}
    indicator_ids: Dict[str, str] = {}
    sco_refs: List[str] = []
    for ioc in _ioc_items(ioc_summary):
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")
        if not value:
            continue
        if ioc_type in {"ipv4", "ipv6"}:
            pattern = f"[ipv4-addr:value = '{value}']"
        elif ioc_type == "domain":
            pattern = f"[domain-name:value = '{value}']"
        elif ioc_type == "url":
            pattern = f"[url:value = '{value}']"
        elif ioc_type in {"sha256", "sha1", "md5"}:
            pattern = f"[file:hashes.'{ioc_type.upper()}' = '{value}']"
        else:
            continue
        indicator_id = f"indicator--{uuid.uuid5(TI_NAMESPACE, 'indicator:' + ioc_type + ':' + value)}"
        indicator_ids[f"{ioc_type}:{value}"] = indicator_id
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": _stix_timestamp(ioc.get("first_seen", "")),
            "indicator_types": ["malicious-activity"],
        }
        _append_stix_object(objects, report_obj, indicator, seen_ids)
        sco = _sco_for_ioc(ioc)
        if sco:
            _append_stix_object(objects, report_obj, sco, seen_ids, reference_from_report=False)
            if sco["id"] not in sco_refs:
                sco_refs.append(sco["id"])

    src_ip = str(session_payload.get("src_ip") or "").strip()
    if src_ip and src_ip not in {"unknown", "-"}:
        src_ioc = {"type": "ipv6" if ":" in src_ip else "ipv4", "value": src_ip}
        sco = _sco_for_ioc(src_ioc)
        if sco:
            _append_stix_object(objects, report_obj, sco, seen_ids, reference_from_report=False)
            if sco["id"] not in sco_refs:
                sco_refs.append(sco["id"])

    identity = _build_identity(now, session_payload)
    has_sightings = bool(indicator_ids)
    has_campaign = bool((session_payload.get("campaign_summary") or report.get("campaign_context") or {}).get("campaign_id"))
    if has_sightings or has_campaign:
        _append_stix_object(objects, report_obj, identity, seen_ids)

    commands = [str(command) for command in session_payload.get("commands") or [] if str(command).strip()]
    if commands:
        command_sequence = {
            "type": "x-honeypot-command-sequence",
            "spec_version": "2.1",
            "id": _stix_id("x-honeypot-command-sequence", "session-commands:" + str(session_id)),
            "created": now,
            "modified": now,
            "x_honeypot_session_id": session_id,
            "x_honeypot_commands": commands[:50],
            "x_honeypot_command_count": len(commands),
        }
        _append_stix_object(objects, report_obj, command_sequence, seen_ids, reference_from_report=False)
        if command_sequence["id"] not in sco_refs:
            sco_refs.append(command_sequence["id"])
    if sco_refs or commands:
        observed_id = _stix_id("observed-data", "session-observed-data:" + str(session_id))
        first_observed = _stix_timestamp(str(session_payload.get("start_time") or report.get("created_at") or ""))
        last_observed = _stix_timestamp(str(session_payload.get("end_time") or session_payload.get("updated_at") or report.get("created_at") or ""))
        observed = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_id,
            "created": now,
            "modified": now,
            "first_observed": first_observed,
            "last_observed": last_observed,
            "number_observed": 1,
            "object_refs": sco_refs,
            "x_honeypot_session_id": session_id,
            "x_honeypot_commands": commands[:50],
            "x_honeypot_event_count": len(session_payload.get("raw_events") or []),
        }
        _append_stix_object(objects, report_obj, observed, seen_ids)

    for marker, indicator_id in sorted(indicator_ids.items()):
        sighting_id = _stix_id("sighting", "session-sighting:" + str(session_id) + ":" + marker)
        sighting = {
            "type": "sighting",
            "spec_version": "2.1",
            "id": sighting_id,
            "created": now,
            "modified": now,
            "sighting_of_ref": indicator_id,
            "where_sighted_refs": [identity["id"]],
            "count": 1,
            "first_seen": _stix_timestamp(str(session_payload.get("start_time") or "")),
            "last_seen": _stix_timestamp(str(session_payload.get("end_time") or session_payload.get("updated_at") or "")),
            "x_honeypot_session_id": session_id,
        }
        _append_stix_object(objects, report_obj, sighting, seen_ids)

    campaign_summary = session_payload.get("campaign_summary") or report.get("campaign_context") or {}
    if isinstance(campaign_summary, dict) and campaign_summary.get("campaign_id"):
        campaign_id_value = str(campaign_summary.get("campaign_id"))
        campaign_id = _stix_id("campaign", "honeypot-campaign:" + campaign_id_value)
        campaign = {
            "type": "campaign",
            "spec_version": "2.1",
            "id": campaign_id,
            "created": now,
            "modified": now,
            "name": f"Honeypot behavioral cluster {campaign_id_value}",
            "description": (
                "Local honeypot behavioral cluster based on observable and command-pattern "
                "similarity. This is not confirmed named-actor attribution."
            ),
            "first_seen": _stix_timestamp(str(campaign_summary.get("first_seen") or session_payload.get("start_time") or "")),
            "last_seen": _stix_timestamp(str(campaign_summary.get("last_seen") or session_payload.get("updated_at") or "")),
            "x_honeypot_campaign_id": campaign_id_value,
            "x_honeypot_matched_existing_campaign": bool(campaign_summary.get("matched_existing_campaign")),
            "x_honeypot_session_count": campaign_summary.get("campaign_session_count") or campaign_summary.get("session_count") or 0,
            "x_honeypot_max_confirmed_severity": campaign_summary.get("max_confirmed_severity") or "",
        }
        _append_stix_object(objects, report_obj, campaign, seen_ids)
        for tid, attack_pattern in ttp_obj_map.items():
            rel_id = _stix_id("relationship", "campaign-uses:" + campaign_id + ":" + attack_pattern["id"])
            _append_stix_object(objects, report_obj, {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now,
                "modified": now,
                "relationship_type": "uses",
                "source_ref": campaign_id,
                "target_ref": attack_pattern["id"],
            }, seen_ids, reference_from_report=False)

    for raw_action in trusted_actions:
        action = _safe_artifact_mapping(raw_action, "action")
        action_id_value = str(action.get("action_id") or action.get("rule_id") or action.get("description") or stable_json(action))
        coa_id = _stix_id("course-of-action", "policy-action:" + action_id_value)
        coa = {
            "type": "course-of-action",
            "spec_version": "2.1",
            "id": coa_id,
            "created": now,
            "modified": now,
            "name": str(action.get("description") or action_id_value),
            "description": str(action.get("rationale") or ""),
            "external_references": _external_references(action.get("references")),
            "x_honeypot_action_id": action.get("action_id") or "",
            "x_honeypot_rule_id": action.get("rule_id") or "",
            "x_honeypot_authority": "deterministic_observed_evidence_policy",
            "x_honeypot_evidence_refs": action.get("evidence_refs") or [],
            "x_honeypot_evidence_scope": action.get("evidence_scope") or [],
            "x_honeypot_requires_manual_approval": True,
            "x_honeypot_safe_to_auto_execute": False,
        }
        _append_stix_object(objects, report_obj, coa, seen_ids)
        for tid in _extract_ttp_ids_from_action(action):
            attack_pattern = ttp_obj_map.get(tid)
            if not attack_pattern:
                continue
            rel_id = _stix_id("relationship", "coa-mitigates:" + coa_id + ":" + attack_pattern["id"])
            _append_stix_object(objects, report_obj, {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now,
                "modified": now,
                "relationship_type": "mitigates",
                "source_ref": coa_id,
                "target_ref": attack_pattern["id"],
            }, seen_ids, reference_from_report=False)

    summary_text = report.get("executive_summary") or report.get("summary") or ""
    if summary_text:
        note_id = _stix_id("note", f"{artifact_version}:{summary_text}")
        note = {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": now,
            "modified": now,
            "abstract": "Threat Hypothesis",
            "content": summary_text,
            "object_refs": report_obj["object_refs"][:1] or [report_obj["id"]],
            "authors": ["Honeypot Threat Hypothesis Engine"],
        }
        _append_stix_object(objects, report_obj, note, seen_ids)

    return {
        "type": "bundle",
        "id": _stix_id("bundle", artifact_version),
        "objects": [report_obj] + objects,
    }


def write_stix_bundle(
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
    output_dir: Path,
    *,
    artifact_version: str = "",
) -> str:
    safe_report = _safe_artifact_mapping(report, "report")
    safe_session_payload = _safe_artifact_mapping(session_payload, "session")
    session_id = safe_session_payload.get("session_id", safe_report.get("session_id", "unknown"))
    version = _resolve_artifact_version(
        artifact_version,
        safe_report,
        safe_session_payload,
    )
    filename = f"{_safe_name(session_id)}_{version}_threat_bundle.json"
    rendered = json.dumps(
        build_stix_bundle(report, session_payload),
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )
    with _reports_directory_handle(output_dir) as directory:
        with _private_artifact_path(directory, filename) as temporary_path:
            temporary_path.write_text(rendered, encoding="utf-8")
        return _verified_artifact_path(directory, filename)


def write_markdown_report(
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
    output_dir: Path,
    *,
    artifact_version: str = "",
) -> str:
    report = _safe_artifact_mapping(report, "report")
    # Keep the same bounded account-label compatibility path as the PDF
    # renderer.  The legacy login_username key remains redacted; only the
    # worker-derived non-secret alias may be shown.
    raw_account = (
        session_payload.get("observed_account_identifier")
        or session_payload.get("login_username")
    )
    session_input = dict(session_payload)
    if raw_account not in (None, "", "[REDACTED]"):
        safe_account = _safe_artifact_text(
            raw_account,
            "observed_account_identifier",
        )
        if safe_account and safe_account != "[REDACTED]":
            session_input["observed_account_identifier"] = safe_account
    session_payload = _safe_artifact_mapping(session_input, "session")
    session_id = session_payload.get("session_id", report.get("session_id", "unknown"))
    version = _resolve_artifact_version(
        artifact_version,
        report,
        session_payload,
    )
    ioc_summary = report.get("ioc_summary") or session_payload.get("ioc_summary") or {}
    lines = [
        "# Threat Intelligence Report",
        "",
        f"Generated: {_artifact_timestamp(report, session_payload)}",
        f"Session: {session_id}",
        f"Source IP: {session_payload.get('src_ip', 'unknown')}",
        f"Source endpoint: {session_payload.get('src_ip', 'Unavailable')}:{session_payload.get('src_port', 'Unavailable')}",
        f"Destination endpoint: {session_payload.get('dst_ip', 'Unavailable')}:{session_payload.get('dst_port', 'Unavailable')}",
        f"Protocol: {session_payload.get('protocol') or session_payload.get('service') or 'Unavailable'}",
        f"Observed account: {session_payload.get('observed_account_identifier') or 'Unavailable'}",
        f"Login attempts: {session_payload.get('login_attempts', 'Unavailable')}",
        f"Authentication success: {session_payload.get('login_success', 'Unavailable')}",
        f"Session end: {session_payload.get('end_time') or session_payload.get('updated_at') or 'Unavailable'}",
        "",
        "## Summary",
        str(
            "Canonical behavioral findings and falsifiable alternatives are listed below."
            if report.get("schema_version") == "session_assessment.v4"
            else (report.get("presentation") or {}).get("summary")
            or report.get("executive_summary") or report.get("summary") or "No summary available."
        ),
        "",
        "## TTPs",
    ]
    for tid in _trusted_ttp_ids(report, session_payload):
        lines.append(f"- {tid}")
    if report.get("schema_version") == "session_assessment.v4":
        lines.extend(["", "## Behavioral Findings"])
        for finding in report.get("behavioral_findings") or []:
            lines.append(
                f"- [{finding.get('status', '')}] {finding.get('statement', '')} "
                f"(finding `{finding.get('finding_id', '')}`; evidence: "
                f"{', '.join(finding.get('evidence_refs') or [])})"
            )
        if not report.get("behavioral_findings"):
            lines.append("- No policy-supported behavioral finding.")
        session_assessment = report.get("session_hypothesis_assessment") or {}
        if isinstance(session_assessment, dict):
            lines.extend(["", "## Session-wide Evidence Assessment"])
            lines.append(
                f"- Status: {session_assessment.get('status', 'unavailable')}"
            )
            graph = session_assessment.get("evidence_graph") or {}
            lines.append(
                "- Evidence graph: "
                f"{graph.get('evidence_nodes', 0)} evidence nodes, "
                f"{graph.get('fact_nodes', 0)} facts, "
                f"{graph.get('relationship_edges', 0)} relationships, "
                f"{graph.get('chain_nodes', 0)} chains"
            )
            for family in session_assessment.get("semantic_families") or []:
                if not isinstance(family, dict):
                    continue
                lines.append(
                    f"- {family.get('semantic_family', 'unknown')}: "
                    f"{family.get('status', 'unavailable')}; "
                    f"facts={family.get('observed_fact_count', 0)}; "
                    f"findings={len(family.get('finding_ids') or [])}; "
                    f"missing={', '.join(family.get('missing_evidence') or []) or 'none recorded'}"
                )
            follow_on = session_assessment.get("follow_on_hypothesis") or {}
            lines.append(
                f"- Follow-on hypothesis: {follow_on.get('status', 'unavailable')}"
                + (
                    f" — {follow_on.get('reason')}"
                    if follow_on.get("reason")
                    else ""
                )
            )
            falsifiers = session_assessment.get("falsifiers") or []
            if falsifiers:
                lines.append("- Observed falsifiers: " + "; ".join(
                    str(item.get("meaning"))
                    for item in falsifiers
                    if isinstance(item, dict) and item.get("meaning")
                ))
        lines.extend(["", "## Falsifiable Hypothesis Alternatives"])
        for hypothesis_set in report.get("hypothesis_sets") or []:
            lines.append(f"- {hypothesis_set.get('question', '')} (`{hypothesis_set.get('hypothesis_set_id', '')}`)")
            for hypothesis in hypothesis_set.get("hypotheses") or []:
                lines.append(
                    f"  - {hypothesis.get('statement', '')} "
                    f"(`{hypothesis.get('hypothesis_id', '')}`)"
                )
        if not report.get("hypothesis_sets"):
            lines.append("- No evidence-bounded alternative set was warranted.")
        provenance = report.get("provenance") or {}
        lines.extend([
            "",
            "## Canonical Provenance",
            f"- Evidence SHA-256: {provenance.get('evidence_sha256', '')}",
            f"- Behavior policy SHA-256: {(provenance.get('behavior_policy') or {}).get('sha256', '')}",
            f"- Classification policy SHA-256: {(provenance.get('classification_policy') or {}).get('sha256', '')}",
            f"- Evaluator Git revision: {provenance.get('evaluator_git_revision', '')}",
        ])
    assessment = report.get("supported_assessment") or {}
    follow_on = report.get("follow_on_hypothesis") or {}
    if report.get("schema_version") == "threat_hypothesis.v2":
        lines.extend(["", "## Evidence-Grounded Assessment"])
        lines.append(str(assessment.get("behavior_summary") or "No trusted behavioral evidence."))
        objectives = assessment.get("possible_objectives") or []
        if objectives:
            for claim in objectives:
                lines.append(
                    f"- [{claim.get('evidence_status', 'insufficient_evidence')}] "
                    f"{claim.get('text', '')} (claim `{claim.get('claim_id', '')}`)"
                )
        else:
            lines.append("- No attacker objective inferred from the observed evidence.")
        lines.extend(["", "## Post-Session Follow-On Hypothesis"])
        if follow_on.get("abstained"):
            lines.append(f"- Abstained: {follow_on.get('abstention_reason', '')}")
        else:
            for claim in follow_on.get("claims") or []:
                lines.append(f"- [{claim.get('evidence_status', '')}] {claim.get('text', '')}")
    evidence_lines = _evidence_layer_summary_lines(report)
    if evidence_lines:
        lines.extend(["", "## Evidence Layers"])
        lines.append("Direct observations, session correlations, and predictions are separated to avoid mixing facts with hypotheses.")
        for line in evidence_lines:
            lines.append(f"- {line}")
        direct_items = _layer_items(report, "direct_command_ttps")
        if direct_items:
            lines.append("")
            lines.append("### Direct Command TTPs")
            for item in direct_items[:20]:
                confidence = item.get("confidence") or {}
                lines.append(
                    f"- {item.get('main_ttp', '')} | {item.get('tactic', '')} | "
                    f"sources={', '.join(item.get('sources') or [])} | "
                    f"avg_confidence={confidence.get('average', '-')}"
                )
        correlated_items = _layer_items(report, "session_correlated_ttps")
        if correlated_items:
            lines.append("")
            lines.append("### Session-Correlated TTPs")
            lines.append("Correlation values below are developer-defined heuristic policy strengths, not probabilities.")
            for item in correlated_items[:20]:
                lines.append(
                    f"- {item.get('main_ttp', '')} | {item.get('predicted_technique', {}).get('tactic', item.get('tactic', ''))} | "
                    f"source_type={item.get('source_type', '')} | heuristic_strength_not_probability={item.get('confidence', '-')}"
                )
        prediction_items = _layer_items(report, "prediction_only_hypotheses")
        if prediction_items:
            lines.append("")
            lines.append("### Prediction-Only Hypotheses")
            for item in prediction_items[:10]:
                lines.append(
                    f"- {item.get('predicted_tactic', '')} | confidence={item.get('confidence', '-')} | "
                    f"source_types={', '.join(item.get('source_types') or [])}"
                )
    actions = _trusted_recommendation_actions(report)
    lines.extend(["", "## Policy-Approved Operator Actions"])
    if actions:
        for action in actions:
            lines.append(
                f"- P{action.get('policy_order', 50)} {action.get('description', '')} "
                f"(rule `{action.get('rule_id', '')}`; manual approval required)"
            )
            lines.append(f"  - Canonical evidence: {', '.join(action.get('evidence_refs') or [])}")
    else:
        lines.append("- No policy-approved operator action matched the available evidence.")
    lines.extend(["", "## IoCs"])
    for item in _ioc_items(ioc_summary):
        lines.append(f"- {item.get('type')}: {item.get('value')} ({item.get('confidence', 'unknown')})")
    filename = f"{_safe_name(session_id)}_{version}_threat_report.md"
    with _reports_directory_handle(output_dir) as directory:
        with _private_artifact_path(directory, filename) as temporary_path:
            temporary_path.write_text("\n".join(lines), encoding="utf-8")
        return _verified_artifact_path(directory, filename)


def write_pdf_report(
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
    output_dir: Path,
    *,
    artifact_version: str = "",
    external_ti_projection: Optional[Dict[str, Any]] = None,
    ai_advisory_projection: Optional[Dict[str, Any]] = None,
    prediction_snapshot: Optional[Dict[str, Any]] = None,
) -> str:
    report = _safe_artifact_mapping(report, "report")
    # The generic artifact scrubber intentionally drops path-shaped fields.
    # Carry only bounded CWD transition metadata into this authenticated PDF;
    # never carry the original event body or command/credential text.
    cwd_metadata: List[Dict[str, str]] = []
    raw_events = session_payload.get("raw_events")
    if isinstance(raw_events, list):
        for event in raw_events[:100]:
            if not isinstance(event, dict) or event.get("eventid") != "cowrie.session.cwd":
                continue
            target = event.get("cwd_path")
            origin = event.get("cwd_from_path")
            if not isinstance(target, str) or not target.startswith("/") or len(target) > 256:
                continue
            if any(ord(character) < 0x20 or ord(character) == 0x7F for character in target):
                continue
            if not isinstance(origin, str) or not origin.startswith("/") or len(origin) > 256:
                origin = ""
            if any(ord(character) < 0x20 or ord(character) == 0x7F for character in origin):
                origin = ""
            cwd_metadata.append({
                "eventid": "cowrie.session.cwd",
                "cwd_path": _safe_artifact_text(target, "cwd_path"),
                "cwd_from_path": _safe_artifact_text(origin, "cwd_from_path") if origin else "",
                "cwd_action": "changed" if origin and origin != target else "entered",
                "cwd_status": "observed",
                "timestamp": _safe_artifact_text(str(event.get("timestamp") or "")[:64], "timestamp"),
            })
    # ``login_username`` is intentionally redacted by the generic credential
    # policy. Preserve a separately named, bounded account label for analyst
    # context when the worker supplied one (or when an older payload still
    # contains a non-redacted username). Never bypass the password/secret
    # scrubber for this compatibility path.
    raw_account = (
        session_payload.get("observed_account_identifier")
        or session_payload.get("login_username")
    )
    session_input = dict(session_payload)
    if raw_account not in (None, "", "[REDACTED]"):
        safe_account = _safe_artifact_text(
            raw_account,
            "observed_account_identifier",
        )
        if safe_account and safe_account != "[REDACTED]":
            session_input["observed_account_identifier"] = safe_account
    session_payload = _safe_artifact_mapping(session_input, "session")
    if cwd_metadata:
        session_payload["raw_events"] = cwd_metadata
    external_ti = (
        _safe_artifact_mapping(external_ti_projection, "external_ti_projection")
        if isinstance(external_ti_projection, dict)
        else {}
    )
    ai_advisory = (
        _safe_artifact_mapping(ai_advisory_projection, "ai_advisory_projection")
        if isinstance(ai_advisory_projection, dict)
        else {}
    )
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise _PDFExportUnavailable("PDF renderer is unavailable") from exc

    session_id = session_payload.get("session_id", report.get("session_id", "unknown"))
    prediction_context = _report_prediction_context(prediction_snapshot, session_id)
    version = _resolve_artifact_version(
        artifact_version,
        report,
        session_payload,
    )
    filename = f"{_safe_name(session_id)}_{version}_threat_report.pdf"
    generated_at = _artifact_timestamp(report, session_payload)
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "FormalTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=22, leading=27, textColor=colors.HexColor("#17365D"),
        alignment=0, spaceAfter=8,
    )
    subtitle = ParagraphStyle(
        "FormalSubtitle", parent=styles["Normal"], fontSize=12, leading=16,
        textColor=colors.HexColor("#5B6573"), spaceAfter=4,
    )
    h1 = ParagraphStyle(
        "FormalHeading1", parent=styles["Heading1"], fontName="Helvetica-Bold",
        fontSize=16, leading=20, textColor=colors.HexColor("#17365D"),
        spaceBefore=4, spaceAfter=8, keepWithNext=True,
    )
    h2 = ParagraphStyle(
        "FormalHeading2", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=11.5, leading=14, textColor=colors.HexColor("#2F5597"),
        spaceBefore=9, spaceAfter=4, keepWithNext=True,
    )
    body = ParagraphStyle(
        "FormalBody", parent=styles["Normal"], fontName="Helvetica",
        fontSize=9.2, leading=13, spaceAfter=5,
    )
    small = ParagraphStyle(
        "FormalSmall", parent=styles["Normal"], fontName="Helvetica",
        fontSize=7.6, leading=9.5, textColor=colors.HexColor("#4F5965"),
        spaceAfter=3,
    )
    table_body = ParagraphStyle(
        "FormalTableBody", parent=body, fontSize=7.6, leading=9.2,
        spaceAfter=0,
    )
    table_header = ParagraphStyle(
        "FormalTableHeader", parent=table_body, fontName="Helvetica-Bold",
        textColor=colors.white,
    )
    bullet = ParagraphStyle(
        "FormalBullet", parent=body, leftIndent=12, firstLineIndent=-8,
        bulletIndent=0, spaceAfter=3,
    )

    def _value(value: Any, default: str = "Unavailable", limit: int = 512) -> str:
        if value is None or value == "":
            return default
        if isinstance(value, bool):
            return "YES" if value else "NO"
        text = str(value)
        if len(text) > limit:
            return text[: limit - 1] + "…"
        return text

    def _p(value: Any, style: ParagraphStyle = body, *, limit: int = 512) -> Paragraph:
        text = escape(_value(value, limit=limit)).replace("\n", "<br/>")
        return Paragraph(text, style)

    def _table(rows: List[List[Any]], widths: List[float]) -> Table:
        converted = []
        for row_index, row in enumerate(rows):
            cell_style = table_header if row_index == 0 else table_body
            converted.append([_p(cell, cell_style, limit=4096) for cell in row])
        # Long evidence/guidance cells must be allowed to continue on the next
        # page.  Without splitInRow, one legitimate bounded policy row can be
        # taller than the remaining frame and ReportLab raises LayoutError,
        # making the otherwise complete report unavailable.
        table = Table(
            converted,
            colWidths=widths,
            repeatRows=1,
            splitInRow=1,
            hAlign="LEFT",
        )
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#C9D2DC")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F7FA")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return table

    def _main_technique(value: Any) -> str:
        text = _value(value, "Unavailable", 80).strip()
        return text.split(".", 1)[0] if text else "Unavailable"

    def _evidence_summary(values: Any) -> str:
        return _evidence_reference_summary(values)

    def _duration_text(start_value: Any, end_value: Any) -> str:
        if not start_value or not end_value:
            return "Unavailable"
        try:
            start = datetime.fromisoformat(str(start_value).replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(end_value).replace("Z", "+00:00"))
            seconds = max((end - start).total_seconds(), 0.0)
        except (TypeError, ValueError):
            return "Unavailable"
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        return f"{seconds / 60.0:.1f} minutes"

    ict = timezone(timedelta(hours=7), name="ICT")

    def _format_timestamp(value: Any) -> str:
        """Render analyst-facing time in ICT while keeping source data unchanged."""

        if value is None or value == "":
            return "Unavailable"
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return _value(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(ict).strftime("%d %b %Y, %H:%M:%S ICT")

    def _duration_value(value: Any, start_value: Any, end_value: Any) -> str:
        observed_interval = _duration_text(start_value, end_value)
        if observed_interval != "Unavailable":
            return observed_interval
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            seconds = max(float(value), 0.0)
            if seconds < 60:
                return f"{seconds:.1f} seconds"
            if seconds < 3600:
                return f"{seconds / 60.0:.1f} minutes"
            return f"{seconds / 3600.0:.1f} hours"
        return _duration_text(start_value, end_value)

    def _freshness_age(value: Any, reference: Any) -> str:
        if not value or not reference:
            return "Unavailable"
        try:
            retrieved = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            rendered = datetime.fromisoformat(str(reference).replace("Z", "+00:00"))
            if retrieved.tzinfo is None:
                retrieved = retrieved.replace(tzinfo=timezone.utc)
            if rendered.tzinfo is None:
                rendered = rendered.replace(tzinfo=timezone.utc)
            seconds = max((rendered - retrieved).total_seconds(), 0.0)
        except (TypeError, ValueError):
            return "Unavailable"
        if seconds < 3600:
            return f"{int(seconds // 60)} minutes old"
        if seconds < 86400:
            return f"{int(seconds // 3600)} hours old"
        return f"{int(seconds // 86400)} days old"

    def _display_list(value: Any, *, limit: int = 8) -> str:
        if not isinstance(value, (list, tuple)):
            return "Unavailable"
        values = [_value(item, "", 100).strip() for item in value]
        values = [item for item in values if item]
        if not values:
            return "Unavailable"
        visible = values[:limit]
        suffix = f"; +{len(values) - limit} more" if len(values) > limit else ""
        return ", ".join(visible) + suffix

    def _present(value: Any) -> bool:
        return value not in (None, "", [], {}, ())

    def _endpoint(address: Any, port: Any) -> str:
        if not _present(address):
            return "Unavailable"
        return (
            f"{_value(address)}:{_value(port)}"
            if _present(port)
            else _value(address)
        )

    def _compact(value: Any, default: str = "Unavailable", limit: int = 360) -> str:
        return _value(value, default=default, limit=limit)

    def _external_evidence_details(item: Dict[str, Any]) -> str:
        extension = item.get("normalized_extension")
        if not isinstance(extension, dict):
            return _value(item.get("summary"), "No normalized provider detail", 800)
        labels = (
            ("abuse_confidence_score", "abuse score"),
            ("total_reports", "reports"),
            ("last_reported_at", "last reported"),
            ("country_code", "country"),
            ("usage_type", "usage"),
            ("domain", "domain"),
            ("isp", "ISP"),
            ("asn", "ASN"),
            ("ports", "ports"),
            ("services", "services"),
            ("hostnames", "hostnames"),
            ("tags", "tags"),
            ("vulnerabilities", "vulnerabilities"),
            ("cpes", "CPEs"),
            ("malicious", "malicious detections"),
            ("suspicious", "suspicious detections"),
            ("malware_family", "malware family"),
            ("pulse_count", "OTX pulses"),
        )
        details: List[str] = []
        for key, label in labels:
            value = extension.get(key)
            if value is None or value == "" or value is False:
                continue
            if isinstance(value, (list, tuple)):
                rendered = _display_list(value, limit=6)
            elif isinstance(value, dict):
                rendered = ", ".join(
                    f"{_value(name, '', 50)}={_value(detail, '', 80)}"
                    for name, detail in list(value.items())[:6]
                )
            else:
                rendered = _value(value, limit=120)
            details.append(f"{label}: {rendered}")
        pulses = extension.get("pulses")
        if isinstance(pulses, list) and pulses:
            if not extension.get("pulse_count"):
                details.append(f"OTX pulses: {len(pulses)}")
            pulse_names = [
                _value(pulse.get("name"), "", 100)
                for pulse in pulses[:2]
                if isinstance(pulse, dict) and isinstance(pulse.get("name"), str)
                and pulse.get("name").strip()
            ]
            if pulse_names:
                details.append(f"pulse examples: {'; '.join(pulse_names)}")
        return "; ".join(details[:10]) or _value(
            item.get("summary"), "No normalized provider detail", 800
        )

    def _is_private_network_indicator(item: Dict[str, Any]) -> bool:
        if str(item.get("type") or "").strip().lower() not in {"ip", "ipv4", "ipv6"}:
            return False
        try:
            address = ipaddress.ip_address(str(item.get("value") or "").strip())
        except ValueError:
            return False
        return not address.is_global

    def _ai_rendered_texts(projection: Dict[str, Any]) -> List[str]:
        advisory = projection.get("advisory") if isinstance(projection.get("advisory"), dict) else {}
        validation = advisory.get("validation") if isinstance(advisory.get("validation"), dict) else {}
        validation_status = str(validation.get("status") or "").strip().lower()
        if validation_status not in {"accepted", "valid"}:
            return []
        rendered = advisory.get("rendered_advisory") if isinstance(advisory.get("rendered_advisory"), dict) else {}
        texts: List[str] = []
        for item in rendered.get("paragraphs") or []:
            if isinstance(item, dict) and str(item.get("text") or "").strip():
                texts.append(str(item.get("text")).strip())
        for item in rendered.get("sections") or []:
            if not isinstance(item, dict):
                continue
            text = item.get("text") or item.get("summary") or item.get("body")
            if str(text or "").strip():
                texts.append(str(text).strip())
        return texts[:3]

    def _ai_selection_summary(projection: Dict[str, Any]) -> Dict[str, str]:
        """Expose only bounded, contract-approved advisory selection IDs."""

        advisory = (
            projection.get("advisory")
            if isinstance(projection.get("advisory"), dict)
            else {}
        )
        rendered = (
            advisory.get("rendered_advisory")
            if isinstance(advisory.get("rendered_advisory"), dict)
            else {}
        )
        validated = (
            advisory.get("validated_advisory")
            if isinstance(advisory.get("validated_advisory"), dict)
            else advisory
        )
        selections = validated.get("template_selections")
        if not isinstance(selections, list):
            selections = rendered.get("paragraphs")
        if not isinstance(selections, list):
            selections = []

        def _ids(values: Any, *, limit: int = 12) -> List[str]:
            if not isinstance(values, (list, tuple)):
                return []
            result: List[str] = []
            for value in values:
                if len(result) >= limit:
                    break
                try:
                    text = _safe_artifact_text(value, "ai_selection")[:160].strip()
                except (TypeError, ValueError):
                    continue
                if text and text != "[REDACTED]" and text not in result:
                    result.append(text)
            return result

        template_ids: List[str] = []
        finding_ids: List[str] = _ids(validated.get("selected_finding_ids"))
        action_ids: List[str] = _ids(validated.get("ranked_action_ids"))
        relationship_ids: List[str] = _ids(validated.get("selected_relationship_ids"))
        limitation_codes: List[str] = _ids(advisory.get("limitation_codes"))
        reason_codes: List[str] = _ids(advisory.get("reason_codes"))
        finding_families: List[str] = []
        for item in selections[:12]:
            if not isinstance(item, dict):
                continue
            template_ids.extend(_ids([item.get("template_id")], limit=1))
            finding_ids.extend(_ids(item.get("finding_ids")))
            action_ids.extend(_ids(item.get("action_ids")))
            relationship_ids.extend(_ids(item.get("relationship_ids")))
            limitation_codes.extend(_ids(item.get("limitation_codes")))
            reason_codes.extend(_ids(item.get("reason_codes")))
        for item in rendered.get("paragraphs") or []:
            if not isinstance(item, dict):
                continue
            finding_families.extend(_ids(item.get("finding_types")))

        def _dedupe(values: List[str]) -> List[str]:
            return list(dict.fromkeys(values))[:12]

        return {
            "templates": ", ".join(_dedupe(template_ids)),
            "finding_ids": ", ".join(_dedupe(finding_ids)),
            "finding_families": ", ".join(_dedupe(finding_families)),
            "action_ids": ", ".join(_dedupe(action_ids)),
            "relationship_ids": ", ".join(_dedupe(relationship_ids)),
            "limitation_codes": ", ".join(_dedupe(limitation_codes)),
            "reason_codes": ", ".join(_dedupe(reason_codes)),
        }

    session_status = (
        "CLOSED" if session_payload.get("is_ended") is True
        else "ACTIVE" if session_payload.get("is_ended") is False
        else _value(session_payload.get("status"), "UNAVAILABLE", 40).upper()
    )
    command_count = session_payload.get("command_count")
    if not isinstance(command_count, int):
        commands = session_payload.get("commands")
        command_count = len(commands) if isinstance(commands, list) else 0
    source_ip = session_payload.get("src_ip") or session_payload.get("source_ip")
    sensor = session_payload.get("sensor_id") or session_payload.get("sensor")
    session_start = session_payload.get("start_time")
    session_updated = session_payload.get("updated_at")
    session_end = session_payload.get("end_time")
    effective_session_end = session_end or (
        session_updated if session_status == "CLOSED" else None
    )
    duration_display = _duration_value(
        session_payload.get("duration"),
        session_start,
        effective_session_end,
    )
    source_port = session_payload.get("src_port")
    destination_ip = session_payload.get("dst_ip")
    destination_port = session_payload.get("dst_port")
    protocol = session_payload.get("protocol") or session_payload.get("service")
    client_version = session_payload.get("client_version")
    hassh = session_payload.get("hassh")
    ja3 = session_payload.get("ja3")
    login_attempts = session_payload.get("login_attempts")
    if not isinstance(login_attempts, int) or isinstance(login_attempts, bool):
        login_attempts = 0
    login_success = session_payload.get("login_success")
    account_visibility = str(
        session_payload.get("observed_account_visibility") or ""
    ).strip().upper()
    observed_account = (
        session_payload.get("observed_account_identifier")
        or None
    )
    if not observed_account and account_visibility == "REDACTED_BEFORE_PERSISTENCE":
        observed_account = "Redacted before persistence"
    elif not observed_account and account_visibility == "NOT_PERSISTED":
        observed_account = "Username not persisted"
    credential_metadata = (
        session_payload.get("credential_metadata")
        if isinstance(session_payload.get("credential_metadata"), dict)
        else {}
    )
    credential_observed = credential_metadata.get("credential_observed")
    if not isinstance(credential_observed, bool):
        credential_observed = bool(login_attempts or login_success)
    password_hash_present = credential_metadata.get("password_hash_present") is True
    password_alias_count = credential_metadata.get("password_hash_alias_count")
    if not isinstance(password_alias_count, int) or isinstance(password_alias_count, bool):
        password_alias_count = 0
    source_geo = session_payload.get("geo")
    source_geo_mapping = source_geo if isinstance(source_geo, dict) else {}
    source_country = (
        source_geo_mapping.get("country")
        or source_geo_mapping.get("country_name")
        or (source_geo if isinstance(source_geo, str) else None)
    )
    source_region = source_geo_mapping.get("region") or source_geo_mapping.get("region_name")
    source_city = source_geo_mapping.get("city")
    source_asn = session_payload.get("asn") or source_geo_mapping.get("asn")
    source_isp = (
        session_payload.get("isp")
        or source_geo_mapping.get("isp")
        or source_geo_mapping.get("organization")
        or source_geo_mapping.get("org")
    )
    command_success_count = len(session_payload.get("commands_success") or [])
    command_failure_count = len(session_payload.get("commands_failed") or [])
    command_outcome_count = command_success_count + command_failure_count
    command_unknown_count = max(command_count - command_outcome_count, 0)
    actions = _trusted_recommendation_actions(report)
    guidance = report.get("response_guidance_v3") if isinstance(report.get("response_guidance_v3"), dict) else {}
    triage = guidance.get("triage") if isinstance(guidance.get("triage"), dict) else {}
    review_priority = str(triage.get("review_priority") or "Unavailable").upper()
    urgency = str(triage.get("urgency") or "Unavailable").replace("_", " ").upper()
    technique_ids = _trusted_ttp_ids(report, session_payload)
    finding_statements: List[str] = []
    hypothesis_statements: List[str] = []
    if report.get("schema_version") == "session_assessment.v4":
        for finding in report.get("behavioral_findings") or []:
            if isinstance(finding, dict) and str(finding.get("statement") or "").strip():
                finding_statements.append(str(finding["statement"]).strip())
        for hypothesis_set in report.get("hypothesis_sets") or []:
            if not isinstance(hypothesis_set, dict):
                continue
            for hypothesis in hypothesis_set.get("hypotheses") or []:
                if isinstance(hypothesis, dict) and str(hypothesis.get("statement") or "").strip():
                    hypothesis_statements.append(str(hypothesis["statement"]).strip())
    elif report.get("schema_version") == "threat_hypothesis.v2":
        assessment = report.get("supported_assessment") or {}
        if isinstance(assessment, dict) and str(assessment.get("behavior_summary") or "").strip():
            finding_statements.append(str(assessment["behavior_summary"]).strip())
        follow_on = report.get("follow_on_hypothesis") or {}
        if isinstance(follow_on, dict):
            for claim in follow_on.get("claims") or []:
                if isinstance(claim, dict) and str(claim.get("text") or "").strip():
                    hypothesis_statements.append(str(claim["text"]).strip())
    ensemble = session_payload.get("ensemble_evidence") or report.get("ensemble_evidence") or {}
    ensemble_results = ensemble.get("results") if isinstance(ensemble, dict) else []
    ensemble_results = [item for item in (ensemble_results or []) if isinstance(item, dict)]
    agreement_count = sum(
        1 for item in ensemble_results
        if str(item.get("model2_relation") or "").upper() == "CORROBORATES"
    )
    disagreement_count = sum(
        1 for item in ensemble_results
        if str(item.get("model2_relation") or "").upper() == "CONTRADICTS"
    )
    external_context = external_ti or (
        session_payload.get("external_ti_summary")
        or session_payload.get("external_ti")
        or {}
    )
    external_summary = (
        external_context.get("external_ti_summary")
        if isinstance(external_context, dict)
        and isinstance(external_context.get("external_ti_summary"), dict)
        else external_context if isinstance(external_context, dict) else {}
    )
    ti_raw_status = str(
        external_context.get("status")
        or external_summary.get("status")
        or "NOT_RECORDED"
    ).upper()
    ti_status_reason = str(
        external_context.get("status_reason")
        or external_summary.get("status_reason")
        or "STATUS_NOT_SPECIFIED"
    ).upper()
    ti_status_reason_text = str(
        external_context.get("status_reason_text")
        or external_summary.get("status_reason_text")
        or TI_STATUS_REASON_TEXT.get(
            ti_status_reason,
            "The external-TI read model did not record a more specific state.",
        )
    )
    ti_status = ti_raw_status
    ti_display_status = _ti_display_status(ti_status)
    ti_display_status_reason = _ti_display_status(ti_status_reason)
    ti_freshness = (
        external_context.get("freshness")
        if isinstance(external_context, dict)
        and isinstance(external_context.get("freshness"), dict)
        else {}
    )
    latest_ti_retrieval = _latest_ti_lookup_at(external_context)
    if technique_ids and ti_status in {"TI_AVAILABLE", "AVAILABLE"}:
        assessment_confidence = "HIGH"
        assessment_confidence_reason = (
            "Direct trusted technique evidence and current external context are available."
        )
    elif technique_ids:
        assessment_confidence = "MEDIUM"
        assessment_confidence_reason = (
            "Direct trusted technique evidence is available, but external context is incomplete or stale."
        )
    else:
        assessment_confidence = "LOW"
        assessment_confidence_reason = (
            "No trusted observed technique was available for a stronger assessment."
        )
    ai_status = str(ai_advisory.get("status") or "UNAVAILABLE").upper()
    data_quality_notes: List[str] = []
    if session_status == "CLOSED" and not session_end:
        data_quality_notes.append("Explicit terminal timestamp unavailable; last update is used")
    if not source_asn and not source_isp:
        data_quality_notes.append("ASN and organization enrichment unavailable")
    if not source_country and not source_region and not source_city:
        data_quality_notes.append("Geographic enrichment unavailable")
    if not client_version and not hassh and not ja3:
        data_quality_notes.append("Client fingerprint data unavailable")
    if login_success is True and not observed_account:
        data_quality_notes.append("Authenticated account identifier unavailable")
    if ti_status not in {"TI_AVAILABLE", "AVAILABLE"}:
        data_quality_notes.append(
            f"External intelligence unavailable or incomplete ({ti_display_status})"
        )
    if external_ti and external_ti.get("ok") is False:
        data_quality_notes.append("External intelligence projection unavailable")
    if not data_quality_notes:
        data_quality_notes.append("No material completeness gap was detected in displayed fields")

    # These fields have historically been initialized with false/zero values
    # by the session/enrichment compatibility layer.  Those defaults are not
    # provider observations: a missing ETI lookup must not be rendered as
    # ``Tor exit=NO``, ``VPN=NO``, or ``risk score=0``.  Preserve positive
    # observations when they are explicitly present, but fail closed for the
    # default negative/zero values.
    reported_tor_exit = True if session_payload.get("is_tor_exit") is True else None
    reported_vpn = True if session_payload.get("is_vpn") is True else None
    reported_risk_score = session_payload.get("risk_score")
    if isinstance(reported_risk_score, bool):
        reported_risk_score = None
    else:
        try:
            if reported_risk_score is None or float(reported_risk_score) <= 0:
                reported_risk_score = None
        except (TypeError, ValueError):
            reported_risk_score = None

    analytic_summary = (
        f"{agreement_count} corroboration(s), {disagreement_count} contradiction(s)"
        if ensemble_results else "No session-bound corroboration result"
    )
    disposition = (
        "PROMPT MANUAL REVIEW"
        if str(triage.get("urgency") or "") == "prompt_review"
        else "ROUTINE MANUAL REVIEW"
        if actions
        else "REVIEW MODEL DISAGREEMENT"
        if disagreement_count
        else "MONITOR / NO POLICY ACTION"
    )
    observed_activity = (
        f"{command_count} command event(s); protocol {protocol or 'Unavailable'}; "
        f"authentication {'succeeded' if login_success is True else 'failed' if login_success is False else 'outcome unavailable'}; "
        f"trusted techniques: {', '.join(technique_ids) if technique_ids else 'none recorded'}"
    )
    recommended_next_step = (
        _compact(actions[0].get("description"), limit=420)
        if actions
        else "No policy-approved operator action matched the available evidence."
    )
    behavioral_assessment = (
        _compact(finding_statements[0], default="No policy-supported behavioral finding was established.", limit=420)
        if finding_statements
        else "No policy-supported behavioral finding was established from this evidence snapshot."
    )
    threat_hypothesis = (
        _compact(hypothesis_statements[0], default="No falsifiable alternative was warranted.", limit=420)
        if hypothesis_statements
        else "No falsifiable alternative was warranted by this evidence snapshot."
    )
    if prediction_context:
        forecast_labels = prediction_context["predictions"] or [
            item["label"] for item in prediction_context["ranking"]
        ]
        next_distinct_summary = (
            f"{prediction_context['status']}: {', '.join(forecast_labels) if forecast_labels else 'no forecast emitted'}; "
            "forecast only, not an observed technique"
        )
    else:
        next_distinct_summary = "Unavailable — no exact session-bound forecast record was supplied."
    overview_rows = [
        ["Document control", "Value"],
        ["Session ID", session_id],
        ["Artifact version", version],
        ["Report schema", report.get("schema_version")],
        ["Evidence timestamp", _format_timestamp(generated_at)],
        ["Session status", session_status],
        ["Source", source_ip],
        ["Sensor", sensor],
        ["Command events", command_count],
        ["Decision authority", "Evidence-bounded advisory; not an automatic enforcement decision"],
    ]
    decision_rows = [
        ["Triage field", "Recorded assessment"],
        ["Disposition", disposition],
        ["Policy review priority", review_priority],
        ["Urgency", urgency],
        ["Assessment confidence", assessment_confidence],
        ["Observed activity", observed_activity],
        ["Recommended next step", recommended_next_step],
        ["Behavioral assessment", behavioral_assessment],
        ["Threat hypothesis", threat_hypothesis],
        ["Next Distinct forecast", next_distinct_summary],
        ["External TI", ti_display_status],
        ["External TI freshness", _ti_display_status(ti_freshness.get("state"))],
        ["Policy-approved actions", len(actions)],
    ]

    story = [
        _p("Threat Intelligence Session Report", title),
        _p("Per-session evidence, infrastructure context, intelligence findings, and response guidance", subtitle),
        Spacer(1, 0.35 * cm),
        HRFlowable(width="100%", thickness=2.2, color=colors.HexColor("#2F5597"), spaceAfter=12),
        _p("CONFIDENTIAL — AUTHORIZED RECIPIENTS", h2),
        _p(
            "This document summarizes one monitored session using the evidence and policy state recorded for that session. "
            "It is intended for analyst triage and audit review; it does not establish attribution or authorize an automatic response. "
            "Credential secret values and raw command text are excluded; the authenticated session view remains the detailed source.",
            body,
        ),
        _p("1. Executive Decision Summary", h1),
        _table(decision_rows, [5.2 * cm, 11.8 * cm]),
        Spacer(1, 0.25 * cm),
        _p("Document Control", h2),
        _table(overview_rows, [4.5 * cm, 12.5 * cm]),
        Spacer(1, 0.35 * cm),
        _p(
            "Command evidence is summarized by count and reviewed technique mapping. Credential secret values and raw command text are never rendered.",
            small,
        ),
        PageBreak(),
    ]

    summary = (
        (
            f"{disposition}. Recorded policy priority is {review_priority}; "
            f"{len(technique_ids)} trusted technique mapping(s) are present. "
            f"Assessment confidence is {assessment_confidence.lower()}; {assessment_confidence_reason} "
            f"Analytic evidence shows {analytic_summary.lower()}; external-TI status is "
            f"{ti_display_status} ({ti_display_status_reason})."
        )
        if report.get("schema_version") == "session_assessment.v4"
        else (report.get("presentation") or {}).get("summary")
        or report.get("executive_summary")
        or report.get("summary")
        or "No summary available."
    )
    raw_events = session_payload.get("raw_events") or session_payload.get("events") or []
    cwd_rows = [["Time", "From", "To", "Action", "Status"]]
    previous_cwd = ""
    if isinstance(raw_events, list):
        for event in raw_events[:100]:
            if not isinstance(event, dict):
                continue
            event_id = str(event.get("eventid") or event.get("event_id") or "").strip().lower()
            if event_id != "cowrie.session.cwd":
                continue
            target_path = event.get("cwd_path")
            if not target_path:
                continue
            from_path = event.get("cwd_from_path") or previous_cwd
            action = event.get("cwd_action") or (
                "changed" if from_path and from_path != target_path else "entered"
            )
            status = event.get("cwd_status") or "observed"
            cwd_rows.append([
                _format_timestamp(event.get("timestamp") or event.get("received_at")),
                _value(from_path, "Initial directory", 256),
                _value(target_path, "Unavailable", 256),
                _value(action, "observed", 80),
                _value(status, "observed", 80),
            ])
            previous_cwd = str(target_path)

    story.extend([
        _p("2. Evidence and Session Context", h1),
        _p(summary, body),
        _p(
            "Interpretation rule: direct observations are separated from session correlations and prediction-only hypotheses. "
            "Model outputs are corroborative and non-authoritative; numeric scores are native model values, not calibrated probabilities.",
            body,
        ),
        _p("2.1 Session and Collection Context", h2),
        _table([
            ["Context field", "Recorded value"],
            ["Session lifecycle", session_status],
            ["Session start", _format_timestamp(session_start)],
            ["Last update", _format_timestamp(session_updated)],
            ["Session end / terminal update", _format_timestamp(effective_session_end)],
            ["Recorded duration", duration_display],
            ["Source endpoint", _endpoint(source_ip, source_port)],
            ["Destination endpoint", _endpoint(destination_ip, destination_port)],
            ["Sensor identifier", sensor],
            ["Protocol / listener", protocol],
            ["ASN", source_asn],
            ["Organization / ISP", source_isp],
            ["Location", ", ".join(str(value) for value in (source_city, source_region, source_country) if value) or None],
            ["Command events", command_count],
            ["Data gaps", "; ".join(data_quality_notes)],
        ], [5.0 * cm, 12.0 * cm]),
        Spacer(1, 0.25 * cm),
        _p("2.2 Connection and Authentication", h2),
        _table([
            ["Authentication / client field", "Recorded value"],
            ["Login attempts", login_attempts],
            ["Authentication success", login_success if isinstance(login_success, bool) else None],
            ["Observed account", observed_account],
            ["Credential observed", credential_observed],
            ["Password value", "REDACTED — plaintext is not retained or rendered"],
            ["Credential correlation available", password_hash_present],
            ["Credential correlation aliases", password_alias_count],
            ["SSH client version", client_version],
            ["HASSH fingerprint", hassh],
            ["JA3 fingerprint", ja3],
            ["Observed command inputs", command_count],
            ["Explicit successful outcomes", command_success_count if command_outcome_count else None],
            ["Explicit failed outcomes", command_failure_count if command_outcome_count else None],
            ["Unknown command outcomes", command_unknown_count],
        ], [5.8 * cm, 11.2 * cm]),
        Spacer(1, 0.25 * cm),
    ])
    cwd_section_offset = 1 if len(cwd_rows) > 1 else 0
    if cwd_section_offset:
        story.extend([
            _p("2.3 Filesystem Activity / Working Directory", h2),
            _table(cwd_rows, [3.7 * cm, 4.0 * cm, 4.0 * cm, 2.8 * cm, 2.5 * cm]),
            _p(
                "Working-directory transitions are direct Cowrie session evidence. Command text and credential values are not included in this table.",
                small,
            ),
            Spacer(1, 0.2 * cm),
        ])
    story.extend([
        _p(f"2.{3 + cwd_section_offset} Evidence Assessment", h2),
        _p(
            "The evidence model is deliberately layered. A direct command observation is stronger than a session correlation, "
            "and a prediction-only hypothesis is not presented as an observed technique. Command inputs are summarized by count "
            "and evidence mapping; credential secret values are never rendered.", body,
        ),
    ])

    evidence_lines = _evidence_layer_summary_lines(report)
    if evidence_lines:
        layer_rows = [["Evidence layer", "Count", "Meaning"]]
        meanings = {
            "Direct command TTPs": "Behavioral-layer count; separately reviewed rule mappings appear below",
            "Session-correlated TTPs": "Policy-bounded session correlation; not a probability",
            "Prediction-only hypotheses": "Forecast only; not an observation",
        }
        for line in evidence_lines:
            label, _, value = line.partition(":")
            display_label = "Direct command TTPs (behavioral layer)" if label == "Direct command TTPs" else label
            layer_rows.append([display_label, value.strip(), meanings.get(label, "Recorded evidence layer")])
        layer_rows.append([
            "Trusted technique mappings",
            len(technique_ids),
            "Reviewed main-technique mappings; may include trusted rule evidence outside the layer summary",
        ])
        story.append(_table(layer_rows, [5.0 * cm, 2.2 * cm, 9.8 * cm]))
    else:
        story.append(_p("No evidence-layer summary was recorded for this session.", body))

    model1_advisory = summarize_session_model1_ttp(
        session_payload.get("classification_events"), session_id=str(session_id)
    )
    story.append(_p("Model1 command-level advisory (not an observed finding)", h2))
    story.append(_p(
        f"{model1_advisory['assessed_command_events']} distinct command event(s) with usable Model1 predictions. "
        "Counts rank items for manual investigation only; they are not confidence or ATT&CK findings. "
        "Model2 binary heads are not ranked or numerically fused here.",
        body,
    ))
    model1_rows = [["Technique", "Supporting commands", "Command references"]]
    for item in model1_advisory["techniques"][:20]:
        model1_rows.append([
            item["technique_id"],
            str(item["supporting_command_events"]),
            ", ".join(ref["command_ref"] for ref in item["evidence_refs"][:8]),
        ])
    if len(model1_rows) > 1:
        story.append(_table(model1_rows, [3.0 * cm, 4.0 * cm, 10.0 * cm]))
    else:
        story.append(_p("No deduplicated command-level Model1 advisory is available.", body))

    story.append(_p("Model2 exact-session shadow evidence", h2))
    model2 = ensemble.get("model2") if isinstance(ensemble, dict) else None
    model2 = model2 if isinstance(model2, dict) else {}
    binding = model2.get("binding") if isinstance(model2.get("binding"), dict) else {}
    model2_bound = (
        model2.get("available") is True
        and str(binding.get("session_id") or "") == str(session_id)
        and all(str(binding.get(key) or "").strip()
                for key in ("run_id", "measurement_id", "episode_id"))
    )
    if model2_bound:
        story.append(_p(
            "A Model2 shadow result is bound to this session. It is corroboration context only; "
            "it does not create an observed finding or authorize response.", body,
        ))
        model2_rows = [["Field", "Stored value"]]
        for label, selected in (
            ("Availability", model2.get("availability")),
            ("Status", model2.get("status")),
            ("Artifact SHA-256", model2.get("artifact_sha256")),
            ("Run ID", binding.get("run_id")),
            ("Measurement ID", binding.get("measurement_id")),
            ("Episode ID", binding.get("episode_id")),
        ):
            model2_rows.append([label, _value(selected, limit=128)])
        story.append(_table(model2_rows, [5.0 * cm, 12.0 * cm]))
        unavailable_heads = model2.get("unavailable_heads")
        if isinstance(unavailable_heads, dict) and unavailable_heads:
            for technique, reason in list(sorted(unavailable_heads.items()))[:8]:
                story.append(_p(
                    f"Unavailable Model2 head {str(technique)[:32]}: {str(reason)[:128]}",
                    small,
                ))
    else:
        story.append(_p(
            "No complete exact-session Model2 binding was available for this report. "
            "Model1 remains the primary classifier; Model2 corroboration is not claimed.",
            body,
        ))

    story.append(_p(f"2.{4 + cwd_section_offset} Trusted Technique Mappings", h2))
    sources = session_payload.get("ttp_sources", {})
    technique_rows = [[
        "Main technique",
        "Tactic",
        "Evidence source",
        "Evidence references",
    ]]
    canonical_evidence = report.get("canonical_evidence") or {}
    observed_records = canonical_evidence.get("observed_trusted_ttps") or []
    if not observed_records:
        observed_records = session_payload.get("observed_trusted_ttps") or []
    record_by_id = {}
    for item in observed_records:
        if isinstance(item, dict):
            record_by_id.setdefault(_main_technique(item.get("technique_id") or item.get("main_ttp")), item)
    for technique_id in _trusted_ttp_ids(report, session_payload):
        main_id = _main_technique(technique_id)
        item = record_by_id.get(main_id, {})
        raw_sources = (
            item.get("sources")
            or item.get("source_ttp_values")
            or sources.get(technique_id)
            or sources.get(main_id)
            or []
        )
        if not isinstance(raw_sources, list):
            raw_sources = [raw_sources]
        raw_tactics = (
            item.get("tactics")
            or item.get("tactic")
            or item.get("predicted_tactic")
        )
        if not isinstance(raw_tactics, (list, tuple, set)):
            raw_tactics = [raw_tactics] if raw_tactics else []
        reference_values: List[Any] = []
        for reference_key in (
            "classification_event_refs",
            "command_evidence_refs",
            "evidence_refs",
            "authority_decision_refs",
        ):
            values = item.get(reference_key) or []
            if isinstance(values, (list, tuple, set)):
                reference_values.extend(values)
            elif values:
                reference_values.append(values)
        event_count = len({
            str(value).strip()
            for value in (item.get("classification_event_refs") or [])
            if str(value).strip()
        })
        source_text = ", ".join(
            _value(value, limit=100) for value in raw_sources if value not in (None, "")
        )
        if event_count:
            source_text = (
                f"{source_text}; " if source_text else ""
            ) + f"{event_count} observed event(s)"
        technique_rows.append([
            main_id,
            _display_list(list(raw_tactics), limit=4) if raw_tactics else None,
            source_text or None,
            _evidence_summary(reference_values),
        ])
    if len(technique_rows) > 1:
        story.append(_table(technique_rows, [3.0 * cm, 3.3 * cm, 3.8 * cm, 6.9 * cm]))
    else:
        story.append(_p(
            "No trusted observed technique was recorded for this session.",
            body,
        ))
    story.append(_p(
        "Technique identifiers are shown at the main-technique level. This report does not introduce or infer ATT&CK sub-techniques.",
        small,
    ))

    story.extend([_p(f"2.{5 + cwd_section_offset} Behavioral Findings and Alternatives", h2)])
    if report.get("schema_version") == "session_assessment.v4":
        findings = report.get("behavioral_findings") or []
        finding_rows = [["Status", "Finding", "Evidence references"]]
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            refs = finding.get("evidence_refs") or []
            finding_rows.append([
                finding.get("status"),
                f"{finding.get('statement', '')} [{finding.get('finding_id', 'unidentified')}]",
                _evidence_summary(refs),
            ])
        if len(finding_rows) > 1:
            story.append(_table(finding_rows, [2.8 * cm, 9.0 * cm, 5.2 * cm]))
        else:
            story.append(_p(
                "No policy-supported behavioral finding was established from the recorded evidence.",
                body,
            ))
        session_assessment = report.get("session_hypothesis_assessment") or {}
        if isinstance(session_assessment, dict):
            story.append(_p(f"2.{6 + cwd_section_offset} Session-wide Evidence Assessment", h2))
            graph = session_assessment.get("evidence_graph") or {}
            story.append(_p(
                "The following ledger evaluates all activated semantic families in this session. "
                "It records evidence and policy gates; it does not promote forecasts or external context into observed behavior.",
                body,
            ))
            family_rows = [["Semantic family", "Status", "Facts", "Findings", "Evidence gate"]]
            for family in session_assessment.get("semantic_families") or []:
                if not isinstance(family, dict):
                    continue
                missing = ", ".join(family.get("missing_evidence") or []) or "none recorded"
                family_rows.append([
                    family.get("semantic_family") or "unknown",
                    family.get("status") or "unavailable",
                    str(family.get("observed_fact_count", 0)),
                    str(len(family.get("finding_ids") or [])),
                    _compact(missing, limit=260),
                ])
            if len(family_rows) > 1:
                story.append(_table(family_rows, [3.1 * cm, 3.2 * cm, 1.4 * cm, 1.5 * cm, 7.0 * cm]))
            else:
                story.append(_p("No activated semantic-family assessment was recorded.", body))
            story.append(_p(
                "Evidence graph: "
                f"{graph.get('evidence_nodes', 0)} evidence nodes, "
                f"{graph.get('fact_nodes', 0)} facts, "
                f"{graph.get('relationship_edges', 0)} relationships, "
                f"{graph.get('chain_nodes', 0)} chains.",
                small,
            ))
            follow_on_assessment = session_assessment.get("follow_on_hypothesis") or {}
            story.append(_p(
                "Follow-on hypothesis status: "
                f"{follow_on_assessment.get('status', 'unavailable')}"
                + (
                    f" — {follow_on_assessment.get('reason')}"
                    if follow_on_assessment.get("reason")
                    else ""
                ),
                body,
            ))
        hypothesis_rows = [["Question / hypothesis set", "Alternative hypotheses"]]
        for hypothesis_set in report.get("hypothesis_sets") or []:
            if not isinstance(hypothesis_set, dict):
                continue
            alternatives = []
            for hypothesis in hypothesis_set.get("hypotheses") or []:
                if isinstance(hypothesis, dict):
                    alternatives.append(
                        f"{hypothesis.get('statement', '')} [{hypothesis.get('hypothesis_id', 'unidentified')}]"
                    )
            hypothesis_rows.append([
                f"{hypothesis_set.get('question', '')} [{hypothesis_set.get('hypothesis_set_id', 'unidentified')}]",
                "\n".join(alternatives) or "No alternatives recorded",
            ])
        story.append(_p(f"2.{7 + cwd_section_offset} Falsifiable Alternatives", h2))
        if len(hypothesis_rows) > 1:
            story.append(_table(hypothesis_rows, [7.5 * cm, 9.5 * cm]))
        else:
            story.append(_p(
                "No evidence-bounded alternative set was warranted by this evidence snapshot.",
                body,
            ))
    elif report.get("schema_version") == "threat_hypothesis.v2":
        assessment = report.get("supported_assessment") or {}
        story.append(_p(assessment.get("behavior_summary") or "No trusted behavioral evidence.", body))
        objectives = assessment.get("possible_objectives") or []
        if objectives:
            for claim in objectives:
                if isinstance(claim, dict):
                    story.append(_p(f"• [{claim.get('evidence_status', 'insufficient_evidence')}] {claim.get('text', '')}", bullet))
        else:
            story.append(_p("• No attacker objective inferred from the observed evidence.", bullet))
        follow_on = report.get("follow_on_hypothesis") or {}
        story.append(_p("2.6 Post-session Follow-on Hypothesis", h2))
        if follow_on.get("abstained"):
            story.append(_p(f"Abstained: {follow_on.get('abstention_reason', '')}", body))
        else:
            claims = follow_on.get("claims") or []
            story.extend(_p(f"• [{claim.get('evidence_status', '')}] {claim.get('text', '')}", bullet) for claim in claims if isinstance(claim, dict))
    else:
        story.append(_p("No version-specific behavioral assessment was recorded.", body))

    story.append(_p("3. External Threat Intelligence", h1))
    story.append(_p("3.1 Intelligence Status and Coverage", h2))
    infrastructure_rows = [["Infrastructure field", "Recorded context"]]
    infrastructure_values = [
        ("Source IP", source_ip),
        ("ASN", source_asn),
        ("Organization / ISP", source_isp),
        ("Country / region / city", ", ".join(str(value) for value in (source_country, source_region, source_city) if value)),
        ("Tor exit", reported_tor_exit),
        ("VPN", reported_vpn),
        ("Host type", session_payload.get("host_type")),
        ("Risk score", reported_risk_score),
        ("Observed open ports", _display_list(session_payload.get("open_ports"))),
        ("Observed services", _display_list(session_payload.get("running_services"))),
        ("Infrastructure tags", _display_list(session_payload.get("infrastructure_tags"))),
    ]
    for label, value in infrastructure_values:
        if _present(value) or isinstance(value, bool) or value == 0:
            infrastructure_rows.append([label, value])
    if len(infrastructure_rows) > 1:
        story.append(_table(infrastructure_rows, [5.2 * cm, 11.8 * cm]))
    else:
        story.append(_p("No external infrastructure context was recorded for this session.", body))
    story.append(_p(
        "ASN, geolocation, service exposure, and reputation are contextual attributes. They do not by themselves establish malicious intent or actor identity.",
        small,
    ))
    story.append(_p("3.2 Provider Findings", h2))
    if isinstance(external_context, dict) and external_context:
        freshness = (
            external_context.get("freshness")
            if isinstance(external_context.get("freshness"), dict)
            else {}
        )
        counts = (
            external_context.get("counts")
            if isinstance(external_context.get("counts"), dict)
            else {}
        )
        def _ti_count(summary_key: str, count_key: str) -> Any:
            if summary_key in external_summary:
                return external_summary.get(summary_key)
            if count_key in counts:
                return counts.get(count_key)
            return None

        cache_count = _ti_count("source_ip_cache_records_found", "source_ip_cache_records")
        story.append(_p(
            f"Provider context: {cache_count if cache_count is not None else 'no'} source-IP lookup results; "
            f"{_ti_count('evidence_returned', 'evidence_returned') or 0} separately linked findings. "
            f"{ti_status_reason_text}",
            body,
        ))
        ti_rows = [
            ["At a glance", "Recorded result"],
            ["Intelligence state", ti_display_status],
            ["Freshness", _ti_display_status(freshness.get("state"))],
            ["Last checked", _format_timestamp(latest_ti_retrieval)],
            ["Eligible observables", _ti_count("eligible_observable_count", "eligible_observables")],
            ["Provider results", cache_count],
        ]
        if external_context.get("ok") is False:
            ti_rows.append(["Projection status", "Projection unavailable"])
        story.append(_table(ti_rows, [5.2 * cm, 11.8 * cm]))
        policy_bindings = external_summary.get("source_ip_cache_policy_bindings") or []
        if policy_bindings:
            story.append(_p(
                "Audit: provider results are non-authoritative context. Policy binding: "
                + ", ".join(str(item) for item in policy_bindings[:3]),
                small,
            ))

        provider_rows = [["Provider", "Status", "Lookup / finding", "Records", "Freshness"]]
        provider_status = external_context.get("provider_status")
        if isinstance(provider_status, dict):
            for provider, provider_item in sorted(provider_status.items()):
                if str(provider).strip().lower() in {"censys", "external_policy"} or not isinstance(provider_item, dict):
                    continue
                status = str(provider_item.get("status") or "unknown").lower()
                record_count = int(provider_item.get("record_count") or 0)
                lookup_status = str(provider_item.get("lookup_status") or "").strip()
                finding_state = str(provider_item.get("finding_state") or "").strip()
                if (
                    record_count == 0
                    and status in {"disabled", "configured", "unknown"}
                    and not lookup_status
                    and not finding_state
                ):
                    continue
                provider_rows.append([
                    provider,
                    status,
                    f"{lookup_status or '—'} / {finding_state or '—'}",
                    record_count,
                    provider_item.get("freshness_state") or "—",
                ])
        if len(provider_rows) > 1:
            story.extend([
                _p("Provider lookup results", h2),
                _table(provider_rows, [3.3 * cm, 3.0 * cm, 4.6 * cm, 2.0 * cm, 4.1 * cm]),
            ])

        evidence_rows = [["Provider / source", "What the provider reported", "Checked / freshness"]]
        for evidence in (external_context.get("evidence") or [])[:10]:
            if not isinstance(evidence, dict):
                continue
            provider = str(evidence.get("provider") or "Unavailable")
            if provider.strip().lower() in {"", "unknown", "not recorded", "censys", "external_policy"}:
                continue
            observable = evidence.get("observable") if isinstance(evidence.get("observable"), dict) else {}
            observable_type = str(
                observable.get("type") or evidence.get("observable_type") or ""
            ).strip()
            observable_value = str(
                observable.get("value") or evidence.get("observable_value") or ""
            ).strip()
            if not observable_type or not observable_value:
                continue
            observable_text = (
                f"{observable_type}: {observable_value}"
            )
            evidence_rows.append([
                provider,
                f"{observable_text}: {_external_evidence_details(evidence)}",
                (f"{_format_timestamp(evidence.get('retrieved_at'))}; "
                 f"{evidence.get('freshness_state') or 'freshness unavailable'}"),
            ])
        remaining_evidence = max(0, 10 - len(evidence_rows) + 1)
        for cache_item in (external_context.get("source_ip_cache") or [])[:remaining_evidence]:
            if not isinstance(cache_item, dict):
                continue
            provider = str(cache_item.get("provider") or "Unavailable")
            if provider.strip().lower() in {"", "unknown", "not recorded", "censys", "external_policy"}:
                continue
            normalized_context = cache_item.get("normalized_context")
            if not isinstance(normalized_context, dict):
                normalized_context = {}
            lookup_status = str(cache_item.get("lookup_status") or "UNAVAILABLE").strip()
            if lookup_status != "OK":
                result = f"Lookup status: {lookup_status}. No provider finding is inferred."
            else:
                result = _external_evidence_details({"normalized_extension": normalized_context})
            cache_freshness = str(cache_item.get("freshness_state") or external_summary.get("source_ip_cache_freshness") or "not recorded")
            evidence_rows.append([
                f"{provider} (source IP)",
                result,
                f"{_format_timestamp(cache_item.get('lookup_at'))}; {cache_freshness}",
            ])
        if len(evidence_rows) > 1:
            story.extend([
                _p("What the providers reported (maximum 10 results)", h2),
                _p("These are third-party observations about the source or artifact, not proof of activity in this Cowrie session. Provider reputation scores are not model confidence.", body),
                _table(evidence_rows, [3.5 * cm, 9.3 * cm, 4.2 * cm]),
            ])
        else:
            story.append(_p(
                f"No usable provider finding is available for this session. "
                f"Current state: {ti_display_status}. {ti_status_reason_text} "
                "This is unavailable context, not a benign verdict.",
                body,
            ))
    else:
        story.append(_p(
            "No read-only external threat-intelligence projection was available for this report. "
            "This absence does not imply that the source or observables are benign.",
            body,
        ))

    story.append(_p("3.3 Analyst Advisory Summary", h2))
    if isinstance(ai_advisory, dict) and ai_advisory:
        advisory_payload = ai_advisory.get("advisory") if isinstance(ai_advisory.get("advisory"), dict) else {}
        ai_validation = advisory_payload.get("validation") if isinstance(advisory_payload.get("validation"), dict) else {}
        ai_rows = [
            ["Advisory field", "Recorded value"],
            ["Status", ai_status],
            ["Validation", ai_validation.get("status") or ai_validation.get("valid") or None],
            ["Authority", advisory_payload.get("authority") or "NON_AUTHORITATIVE"],
        ]
        selection_summary = _ai_selection_summary(ai_advisory)
        selection_parts = [
            f"{label}: {value}"
            for label, value in (
                ("templates", selection_summary["templates"]),
                ("findings", selection_summary["finding_ids"]),
                ("actions", selection_summary["action_ids"]),
                ("relationships", selection_summary["relationship_ids"]),
                ("limitations", selection_summary["limitation_codes"]),
                ("reasons", selection_summary["reason_codes"]),
            )
            if value
        ]
        if selection_parts:
            ai_rows.append(["Contract selections", "; ".join(selection_parts)])
        story.append(_table(ai_rows, [5.2 * cm, 11.8 * cm]))
        rendered_texts = _ai_rendered_texts(ai_advisory)
        if rendered_texts:
            story.append(_p("Bounded advisory narrative", h2))
            for advisory_text in rendered_texts:
                story.append(_p(advisory_text, body, limit=1200))
        else:
            story.append(_p(
                "No rendered advisory narrative was stored. Validated AI selections, "
                "when listed above, remain available for analyst review; the canonical "
                "evidence and policy guidance remain authoritative.",
                body,
            ))
        story.append(_p(
            "This AI projection is read at PDF generation time and may be newer than "
            "the immutable deterministic assessment stored when the session closed.",
            small,
        ))
    else:
        story.append(_p("No separate AI advisory projection was available for this session.", body))

    story.append(_p("3.4 Next Distinct Forecast Context", h2))
    if prediction_context:
        forecast_labels = prediction_context["predictions"] or [
            item["label"] for item in prediction_context["ranking"]
        ]
        forecast_rows = [
            ["Forecast field", "Recorded value"],
            ["Status", prediction_context["status"]],
            ["Predicted next behavior phase(s)", ", ".join(forecast_labels) or None],
            ["Generated", _format_timestamp(prediction_context["generated_at"])],
            ["Snapshot ID", prediction_context["snapshot_id"] or None],
            ["Authority", prediction_context["authority"]],
        ]
        for label, key in (
            ("Run ID", "run_id"),
            ("Measurement ID", "measurement_id"),
            ("Episode ID", "episode_id"),
            ("Model ID", "model_id"),
            ("Model artifact SHA-256", "model_artifact_sha256"),
            ("Feature contract SHA-256", "feature_contract_sha256"),
        ):
            if prediction_context.get(key):
                forecast_rows.append([label, prediction_context[key]])
        if prediction_context["reason"]:
            forecast_rows.insert(3, ["Status explanation", prediction_context["reason"]])
        story.append(_table(forecast_rows, [5.2 * cm, 11.8 * cm]))
        if prediction_context["ranking"]:
            story.append(_p("Bounded forecast ranking", small))
            story.append(_table(
                [["Rank", "Candidate behavior phase"]]
                + [[item["rank"], item["label"]] for item in prediction_context["ranking"]],
                [2.5 * cm, 14.5 * cm],
            ))
        story.append(_p(
            "This is a session-bound forecast retained for analyst context only. It is not an observed technique, "
            "does not establish intent, and cannot select an alert or response action.",
            small,
        ))
    else:
        story.append(_p(
            "No exact session-bound Next Distinct forecast was recorded for this report. "
            "The report does not substitute a forecast from another session or from an unrelated sidecar run.",
            body,
        ))

    story.append(_p("4. Policy-approved Operator Guidance", h1))
    action_rows = [["Priority", "Policy-approved action", "Evidence references", "Execution"]]
    for action in actions[:20]:
        if isinstance(action, dict):
            action_rows.append([
                f"P{action.get('policy_order', 50)}",
                action.get("description"),
                _evidence_summary(action.get("evidence_refs") or []),
                "Manual approval required; automatic execution not implemented",
            ])
    if len(action_rows) == 1:
        action_rows.append(["—", "No policy-approved operator action matched the available evidence.", "—", "No action"])
    story.append(_table(action_rows, [1.8 * cm, 7.4 * cm, 4.5 * cm, 3.3 * cm]))

    external_ioc_rows = [["Type", "Value", "Confidence"]]
    internal_ioc_rows = [["Type", "Value", "Interpretation"]]
    ioc_summary = report.get("ioc_summary") or session_payload.get("ioc_summary") or {}
    for item in _ioc_items(ioc_summary):
        if isinstance(item, dict):
            if _is_private_network_indicator(item):
                internal_ioc_rows.append([
                    item.get("type"),
                    item.get("value"),
                    "Private/reserved network context; not presented as an external IoC",
                ])
            else:
                external_ioc_rows.append([
                    item.get("type"), item.get("value"), item.get("confidence") or "unknown",
                ])
    if destination_ip and _is_private_network_indicator(
        {"type": "ip", "value": destination_ip}
    ):
        destination_value = (
            f"{destination_ip}:{destination_port}"
            if destination_port not in (None, "")
            else destination_ip
        )
        if not any(str(row[1]) == str(destination_value) for row in internal_ioc_rows[1:]):
            internal_ioc_rows.append([
                "destination endpoint",
                destination_value,
                "Private/reserved monitored destination; infrastructure context, not an external IoC",
            ])
    if source_ip and not _is_private_network_indicator({"type": "ip", "value": source_ip}):
        if not any(str(row[1]) == str(source_ip) for row in external_ioc_rows[1:]):
            external_ioc_rows.append(["ipv4", source_ip, "observed source"])
    if len(external_ioc_rows) == 1:
        external_ioc_rows.append(["—", "No external indicators of compromise recorded.", "—"])
    story.extend([
        _p("4.1 External Indicators", h2),
        _table(external_ioc_rows, [3.0 * cm, 10.0 * cm, 4.0 * cm]),
    ])
    if len(internal_ioc_rows) == 1:
        internal_ioc_rows.append([
            "—",
            "No private/reserved infrastructure indicator was recorded.",
            "—",
        ])
    story.extend([
        _p("4.2 Internal Infrastructure Context", h2),
        _table(internal_ioc_rows, [3.0 * cm, 6.0 * cm, 8.0 * cm]),
    ])

    fingerprint_rows = [["Fingerprint type", "Value", "Interpretation"]]
    if hassh:
        fingerprint_rows.append(["HASSH", hassh, "Observed SSH client fingerprint; useful for cross-session correlation, not attribution"])
    if ja3:
        fingerprint_rows.append(["JA3", ja3, "Observed TLS client fingerprint; useful for cross-session correlation, not attribution"])
    if client_version:
        fingerprint_rows.append(["Client version", client_version, "Client-declared protocol implementation"])
    if len(fingerprint_rows) > 1:
        story.extend([
            _p("4.3 Client and Protocol Fingerprints", h2),
            _table(fingerprint_rows, [3.2 * cm, 6.2 * cm, 7.6 * cm]),
        ])

    campaign_summary = session_payload.get("campaign_summary")
    if isinstance(campaign_summary, dict) and campaign_summary:
        campaign_rows = [
            ["Campaign correlation field", "Recorded value"],
            ["Campaign ID", campaign_summary.get("campaign_id")],
            ["First observed", _format_timestamp(campaign_summary.get("first_seen"))],
            ["Last observed", _format_timestamp(campaign_summary.get("last_seen"))],
            ["Related sessions", campaign_summary.get("session_count")],
            ["Shared indicators", campaign_summary.get("shared_indicator_count")],
        ]
        story.extend([
            _p("4.4 Related Session Context", h2),
            _table(campaign_rows, [5.2 * cm, 11.8 * cm]),
            _p("Correlation indicates shared observables or behavior; it does not establish actor identity.", small),
        ])

    story.extend([_p("5. Provenance, Limitations, and Integrity", h1)])
    provenance = report.get("provenance") or {}
    behavior_policy = provenance.get("behavior_policy") if isinstance(provenance.get("behavior_policy"), dict) else {}
    classification_policy = provenance.get("classification_policy") if isinstance(provenance.get("classification_policy"), dict) else {}
    provenance_rows = [
        ["Integrity field", "Recorded value"],
        ["Artifact version", version],
        ["Evidence SHA-256", provenance.get("evidence_sha256")],
        ["Behavior policy SHA-256", behavior_policy.get("sha256")],
        ["Classification policy SHA-256", classification_policy.get("sha256")],
        ["Evaluator revision", provenance.get("evaluator_git_revision")],
        ["ETI projection", f"{ti_display_status} @ {_format_timestamp(latest_ti_retrieval)}" if isinstance(external_context, dict) else None],
        ["ETI compatibility status", ti_display_status],
        ["ETI state reason", ti_display_status_reason],
        ["AI advisory projection", f"{ai_status} / {ai_advisory.get('advisory_id') or 'no advisory ID'}" if isinstance(ai_advisory, dict) else None],
        ["Report generation", "Deterministic artifact rendering; source report/session remain authoritative"],
    ]
    story.append(_table(provenance_rows, [5.2 * cm, 11.8 * cm]))
    story.append(_p("Limitations and interpretation boundaries", h2))
    for limitation in (
        "Assessment confidence expresses evidence completeness and corroboration; it is not a calibrated probability.",
        "Analytic outputs are advisory evidence; this report does not authorize automatic enforcement.",
        "Technique claims are limited to recorded evidence and policy-supported correlations.",
        "Sub-technique inference is outside the configured scope and is not added by this report.",
        "Absence of a value means unavailable or unrecorded data; the renderer never substitutes zero.",
        "Attribution, intent, and actor identity are not established by this session report.",
        "Command inputs are summarized by count and evidence mapping; raw credential values are never rendered.",
        "External TI and AI advisory sections are read-only presentation context and cannot modify the canonical assessment.",
    ):
        story.append(_p(f"• {limitation}", bullet))
    story.extend([
        Spacer(1, 0.45 * cm),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#8796A5")),
        _p("CONFIDENTIAL — For authorized recipients only. Do not redistribute.", small),
    ])

    document_title = f"Threat Intelligence Session Report — {session_id}"

    def _decorate_page(canvas: Any, document: Any) -> None:
        canvas.saveState()
        width, height = A4
        canvas.setTitle(document_title)
        canvas.setAuthor("Threat Intelligence Monitoring System")
        canvas.setSubject("Evidence-bounded per-session threat intelligence report")
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.setFillColor(colors.HexColor("#5B6573"))
        canvas.drawString(2 * cm, height - 1.15 * cm, "THREAT INTELLIGENCE MONITORING SYSTEM")
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(width - 2 * cm, height - 1.15 * cm, "CONFIDENTIAL")
        canvas.setStrokeColor(colors.HexColor("#C9D2DC"))
        canvas.setLineWidth(0.45)
        canvas.line(2 * cm, height - 1.35 * cm, width - 2 * cm, height - 1.35 * cm)
        canvas.line(2 * cm, 1.35 * cm, width - 2 * cm, 1.35 * cm)
        canvas.setFillColor(colors.HexColor("#5B6573"))
        canvas.setFont("Helvetica", 7)
        canvas.drawString(2 * cm, 0.95 * cm, f"Session {_value(session_id, limit=72)}")
        canvas.drawRightString(width - 2 * cm, 0.95 * cm, f"Page {document.page}")
        canvas.restoreState()

    with _reports_directory_handle(output_dir) as directory:
        with _private_artifact_path(directory, filename) as temporary_path:
            doc = SimpleDocTemplate(
                str(temporary_path),
                pagesize=A4,
                leftMargin=2 * cm,
                rightMargin=2 * cm,
                topMargin=1.8 * cm,
                bottomMargin=1.8 * cm,
                invariant=1,
                title=document_title,
                author="Threat Intelligence Monitoring System",
                subject="Evidence-bounded per-session threat intelligence report",
            )
            doc.build(story, onFirstPage=_decorate_page, onLaterPages=_decorate_page)
        return _verified_artifact_path(directory, filename)


def render_pdf_report_bytes(
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
    *,
    artifact_version: str = "",
    external_ti_projection: Optional[Dict[str, Any]] = None,
    ai_advisory_projection: Optional[Dict[str, Any]] = None,
    prediction_snapshot: Optional[Dict[str, Any]] = None,
) -> bytes:
    """Render one authenticated, deterministic PDF without persistent writes.

    The session download endpoint uses this for existing reports that were
    originally generated before the optional PDF renderer was installed. The
    temporary directory is outside the configured artifact directory, so a
    download cannot mutate the canonical report store or MongoDB. Optional TI,
    AI, and exact-session prediction inputs are already-materialized read
    projections used only for this presentation; this function never invokes
    a provider or model.
    """

    with tempfile.TemporaryDirectory(prefix="session-report-pdf-") as temporary_dir:
        path = Path(write_pdf_report(
            report,
            session_payload,
            Path(temporary_dir),
            artifact_version=artifact_version,
            external_ti_projection=external_ti_projection,
            ai_advisory_projection=ai_advisory_projection,
            prediction_snapshot=prediction_snapshot,
        ))
        return path.read_bytes()


def _artifact_file_record(
    directory: _ReportsDirectory,
    kind: str,
    path_text: str,
) -> Dict[str, Any]:
    path = Path(path_text)
    if path.parent != directory.path:
        raise ValueError("artifact path escaped the reports directory")
    _assert_reports_directory_identity(directory)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path.name, flags, dir_fd=directory.descriptor)
    digest = hashlib.sha256()
    try:
        metadata = os.fstat(descriptor)
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(descriptor)
    media_types = {
        "json": "application/json",
        "stix": "application/stix+json",
        "markdown": "text/markdown",
        "pdf": "application/pdf",
        "pdf_fallback_markdown": "text/markdown",
    }
    return {
        "kind": kind,
        "filename": path.name,
        "media_type": media_types.get(kind, "application/octet-stream"),
        "sha256": digest.hexdigest(),
        "size_bytes": metadata.st_size,
    }


def _write_artifact_integrity_manifest(
    directory: _ReportsDirectory,
    artifacts: Dict[str, Any],
    *,
    artifact_version: str,
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
) -> str:
    entries = [
        _artifact_file_record(directory, kind, path_text)
        for kind, path_text in sorted(artifacts.items())
        if kind in {
            "json",
            "stix",
            "markdown",
            "pdf",
            "pdf_fallback_markdown",
        }
        and isinstance(path_text, str)
    ]
    manifest = {
        "schema_version": "report_artifact_manifest.v1",
        "artifact_version": artifact_version,
        "source_report_sha256": hashlib.sha256(
            stable_json(report).encode("utf-8")
        ).hexdigest(),
        "source_session_sha256": hashlib.sha256(
            stable_json(session_payload).encode("utf-8")
        ).hexdigest(),
        "generated_at": _artifact_timestamp(report, session_payload),
        "artifacts": entries,
    }
    rendered = (
        json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n"
    )
    manifest_sha256 = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    filename = (
        f"{artifact_version}_artifact_manifest_{manifest_sha256}.json"
    )
    with _private_artifact_path(directory, filename) as temporary_path:
        temporary_path.write_text(rendered, encoding="utf-8")
    return _verified_artifact_path(directory, filename)


def validate_report_artifact_manifest(path_text: str | Path) -> List[str]:
    """Verify a manifest filename digest and every bound artifact file."""

    path = Path(path_text).resolve()
    match = _INTEGRITY_MANIFEST_PATTERN.fullmatch(path.name)
    if not match:
        return ["artifact manifest filename is invalid"]
    errors: List[str] = []
    try:
        with _reports_directory_handle(path.parent) as directory:
            manifest_record = _artifact_file_record(
                directory, "integrity_manifest", str(path)
            )
            if manifest_record["sha256"] != match.group(1):
                errors.append("artifact manifest SHA-256 mismatch")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path.name, flags, dir_fd=directory.descriptor)
            try:
                blocks = []
                while True:
                    block = os.read(descriptor, 1024 * 1024)
                    if not block:
                        break
                    blocks.append(block)
            finally:
                os.close(descriptor)
            manifest = json.loads(b"".join(blocks).decode("utf-8"))
            if (
                not isinstance(manifest, dict)
                or manifest.get("schema_version")
                != "report_artifact_manifest.v1"
            ):
                return errors + ["artifact manifest schema is invalid"]
            if not _ARTIFACT_VERSION_PATTERN.fullmatch(
                str(manifest.get("artifact_version") or "")
            ):
                errors.append("artifact manifest version is invalid")
            entries = manifest.get("artifacts")
            if not isinstance(entries, list):
                return errors + ["artifact manifest entries are invalid"]
            seen_kinds: set[str] = set()
            seen_filenames: set[str] = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    errors.append("artifact manifest entry is invalid")
                    continue
                kind = str(entry.get("kind") or "")
                filename = str(entry.get("filename") or "")
                if (
                    not kind
                    or kind in seen_kinds
                    or not filename
                    or Path(filename).name != filename
                ):
                    errors.append("artifact manifest entry identity is invalid")
                    continue
                seen_kinds.add(kind)
                if filename in seen_filenames:
                    # A PDF fallback may intentionally point at the canonical
                    # Markdown file; both records must still hash identically.
                    if kind != "pdf_fallback_markdown":
                        errors.append("artifact manifest filename is duplicated")
                seen_filenames.add(filename)
                actual = _artifact_file_record(
                    directory,
                    kind,
                    str(directory.path / filename),
                )
                if actual["sha256"] != str(entry.get("sha256") or ""):
                    errors.append(f"artifact SHA-256 mismatch: {kind}")
                if actual["size_bytes"] != entry.get("size_bytes"):
                    errors.append(f"artifact size mismatch: {kind}")
    except (
        OSError,
        UnicodeError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ):
        errors.append("artifact manifest verification failed")
    return errors


def attach_report_artifacts(report: Dict[str, Any], session_payload: Dict[str, Any], config: ProductionConfig) -> Dict[str, Any]:
    source_report = report
    source_session_payload = session_payload
    safe_report = _safe_artifact_mapping(report, "report")
    if not config.enable_artifacts:
        return safe_report
    safe_report.pop("artifacts", None)
    safe_session = _safe_artifact_mapping(session_payload, "session")
    artifact_version = _artifact_version_id(safe_report, safe_session)
    artifacts: Dict[str, Any] = {}
    with _prepare_reports_directory(config.reports_dir) as output_dir:
        try:
            artifacts["json"] = write_json_report(
                safe_report,
                safe_session.get(
                    "session_id",
                    safe_report.get("session_id", "unknown"),
                ),
                output_dir,
                artifact_version=artifact_version,
            )
        except _ReportsDirectoryIdentityChanged:
            raise
        except Exception as exc:
            artifacts["json_error"] = _safe_artifact_error(exc)
        if config.enable_stix_export:
            try:
                artifacts["stix"] = write_stix_bundle(
                    source_report,
                    source_session_payload,
                    output_dir,
                    artifact_version=artifact_version,
                )
            except _ReportsDirectoryIdentityChanged:
                raise
            except Exception as exc:
                artifacts["stix_error"] = _safe_artifact_error(exc)
        try:
            artifacts["markdown"] = write_markdown_report(
                safe_report,
                safe_session,
                output_dir,
                artifact_version=artifact_version,
            )
        except _ReportsDirectoryIdentityChanged:
            raise
        except Exception as exc:
            artifacts["markdown_error"] = _safe_artifact_error(exc)
        if config.enable_pdf_export:
            try:
                artifacts["pdf"] = write_pdf_report(
                    safe_report,
                    safe_session,
                    output_dir,
                    artifact_version=artifact_version,
                )
            except _PDFExportUnavailable:
                if artifacts.get("markdown"):
                    artifacts["pdf_fallback_markdown"] = artifacts["markdown"]
                else:
                    artifacts["pdf_error"] = artifacts.get(
                        "markdown_error",
                        "markdown fallback unavailable",
                    )
            except _ReportsDirectoryIdentityChanged:
                raise
            except Exception as exc:
                artifacts["pdf_error"] = _safe_artifact_error(exc)
        try:
            artifacts["integrity_manifest"] = (
                _write_artifact_integrity_manifest(
                    output_dir,
                    artifacts,
                    artifact_version=artifact_version,
                    report=safe_report,
                    session_payload=safe_session,
                )
            )
        except _ReportsDirectoryIdentityChanged:
            raise
        except Exception as exc:
            artifacts["integrity_manifest_error"] = _safe_artifact_error(exc)
        _assert_reports_directory_identity(output_dir)
    safe_report["artifacts"] = artifacts
    return _safe_artifact_mapping(safe_report, "report")
